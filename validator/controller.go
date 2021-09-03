package validator

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/bloxapp/eth2-key-manager/core"
	"github.com/bloxapp/ssv/beacon"
	"github.com/bloxapp/ssv/eth1"
	"github.com/bloxapp/ssv/network"
	"github.com/bloxapp/ssv/pubsub"
	"github.com/bloxapp/ssv/storage/basedb"
	"github.com/bloxapp/ssv/utils/rsaencryption"
	validatorstorage "github.com/bloxapp/ssv/validator/storage"
	"go.uber.org/zap"
	"sync"
	"time"

	spec "github.com/attestantio/go-eth2-client/spec/phase0"
)

// ControllerOptions for controller struct creation
type ControllerOptions struct {
	Context                    context.Context
	DB                         basedb.IDb
	Logger                     *zap.Logger
	SignatureCollectionTimeout time.Duration `yaml:"SignatureCollectionTimeout" env:"SIGNATURE_COLLECTION_TIMEOUT" env-default:"5s" env-description:"Timeout for signature collection after consensus"`
	ETHNetwork                 *core.Network
	Network                    network.Network
	Beacon                     beacon.Beacon
	Shares                     []validatorstorage.ShareOptions `yaml:"Shares"`
	ShareEncryptionKeyProvider eth1.ShareEncryptionKeyProvider
}

// IController interface
type IController interface {
	ListenToEth1Events(cn pubsub.SubjectChannel)
	StartValidators()
	GetValidatorsPubKeys() [][]byte
	GetValidatorsIndices() []spec.ValidatorIndex
	GetValidator(pubKey string) (*Validator, bool)
	NewValidatorSubject() pubsub.Subscriber
}

// Controller struct that manages all validator shares
type controller struct {
	context                    context.Context
	collection                 validatorstorage.ICollection
	logger                     *zap.Logger
	signatureCollectionTimeout time.Duration
	beacon                     beacon.Beacon
	// TODO remove after IBFT refactor
	network    network.Network
	db         basedb.IDb
	ethNetwork *core.Network

	validatorsMap       map[string]*Validator
	newValidatorSubject pubsub.Subject

	shareEncryptionKeyProvider eth1.ShareEncryptionKeyProvider

	// locks
	validatorL sync.RWMutex
}

// NewController creates new validator controller
func NewController(options ControllerOptions) IController {
	collection := validatorstorage.NewCollection(validatorstorage.CollectionOptions{
		DB:     options.DB,
		Logger: options.Logger,
	})

	collection.LoadMultipleFromConfig(options.Shares)

	ctrl := controller{
		collection:                 collection,
		context:                    options.Context,
		logger:                     options.Logger.With(zap.String("component", "validatorsController")),
		signatureCollectionTimeout: options.SignatureCollectionTimeout,
		beacon:                     options.Beacon,
		db:                         options.DB,
		network:                    options.Network,
		ethNetwork:                 options.ETHNetwork,
		newValidatorSubject: pubsub.NewSubject(options.Logger.With(
			zap.String("which", "validator/controller/validator-subject"))),
		validatorsMap:              make(map[string]*Validator),
		shareEncryptionKeyProvider: options.ShareEncryptionKeyProvider,

		// locks
		validatorL: sync.RWMutex{},
	}

	return &ctrl
}

// ListenToEth1Events is listening to events coming from eth1 client
func (c *controller) ListenToEth1Events(cn pubsub.SubjectChannel) {
	for e := range cn {
		if event, ok := e.(eth1.Event); ok {
			if validatorAddedEvent, ok := event.Data.(eth1.ValidatorAddedEvent); ok {
				c.handleValidatorAddedEvent(validatorAddedEvent)
			}
		}
	}
}

// setupValidators for each validatorShare with proper ibft wrappers
func (c *controller) setupValidators() map[string]*Validator {
	shares, err := c.getAllValidatorShares()
	if err != nil {
		c.logger.Fatal("failed to get validators shares", zap.Error(err))
	}
	if len(shares) == 0 {
		c.logger.Info("could not find validators")
		return c.validatorsMap
	}
	c.logger.Info("starting validators setup...")
	for _, validatorShare := range shares {
		pubKey := validatorShare.PublicKey.SerializeToHexStr()
		if _, ok := c.GetValidator(pubKey); ok {
			c.logger.Debug("validator was initialized already..",
				zap.String("pubKey", validatorShare.PublicKey.SerializeToHexStr()))
			continue
		}
		printValidatorShare(c.logger, validatorShare)
		v := New(Options{
			Context:                    c.context,
			SignatureCollectionTimeout: c.signatureCollectionTimeout,
			Logger:                     c.logger,
			Share:                      validatorShare,
			Network:                    c.network,
			ETHNetwork:                 c.ethNetwork,
			Beacon:                     c.beacon,
		}, c.db)
		if added := c.AddValidator(pubKey, v); !added {
			c.logger.Debug("failed to add validator", zap.Error(err))
		}
	}
	c.logger.Info("setup validators done successfully", zap.Int("count", len(c.validatorsMap)))
	return c.validatorsMap
}

// StartValidators functions (queue streaming, msgQueue listen, etc)
func (c *controller) StartValidators() {
	validators := c.setupValidators()
	for _, v := range validators {
		if err := v.Start(); err != nil {
			c.logger.Error("failed to start validator", zap.Error(err))
			continue
		}
	}
}

// NewValidatorSubject returns the validators subject
func (c *controller) NewValidatorSubject() pubsub.Subscriber {
	return c.newValidatorSubject
}

func (c *controller) handleValidatorAddedEvent(validatorAddedEvent eth1.ValidatorAddedEvent) {
	l := c.logger.With(zap.String("validatorPubKey", hex.EncodeToString(validatorAddedEvent.PublicKey)))
	l.Debug("handles validator added event")
	operatorPrivKey, found, err := c.shareEncryptionKeyProvider()
	if !found {
		l.Error("failed to find operator private key")
		return
	}
	if err != nil {
		l.Error("failed to get operator private key")
		return
	}
	var operatorPubKey string
	if operatorPrivKey != nil {
		operatorPubKey, err = rsaencryption.ExtractPublicKey(operatorPrivKey)
		if err != nil {
			l.Error("failed to extract operator public key")
			return
		}
	}
	validatorShare, err := ShareFromValidatorAddedEvent(validatorAddedEvent, operatorPubKey)
	if err != nil {
		l.Error("failed to create share", zap.Error(err))
		return
	}
	_, found, err = c.getValidatorShare(validatorShare.PublicKey.Serialize())
	if err != nil {
		l.Error("could not check if validator share exits", zap.Error(err))
		return
	}
	if found { // validator share exists, do not add.
		return
	}

	if len(validatorShare.Committee) > 0 {
		if err := c.saveValidatorShare(validatorShare); err != nil {
			l.Error("failed to save validator share", zap.Error(err))
			return
		}
		l.Debug("validator share was saved")
		c.onNewValidatorShare(validatorShare)
	}
}

func (c *controller) onNewValidatorShare(validatorShare *validatorstorage.Share) {
	pubKeyHex := validatorShare.PublicKey.SerializeToHexStr()
	if _, exist := c.GetValidator(pubKeyHex); exist {
		c.logger.Debug("skip setup for known validator",
			zap.String("pubKeyHex", pubKeyHex))
		return
	}
	// setup validator
	validatorOpts := Options{
		Context:                    c.context,
		Logger:                     c.logger,
		Share:                      validatorShare,
		Network:                    c.network,
		Beacon:                     c.beacon,
		ETHNetwork:                 c.ethNetwork,
		SignatureCollectionTimeout: c.signatureCollectionTimeout,
	}
	v := New(validatorOpts, c.db)
	if added := c.AddValidator(pubKeyHex, v); added {
		// start validator
		if err := v.Start(); err != nil {
			c.logger.Error("failed to start validator",
				zap.Error(err), zap.String("pubKeyHex", pubKeyHex))
		} else {
			c.logger.Debug("validator started", zap.String("pubKeyHex", pubKeyHex))
		}
		c.newValidatorSubject.Notify(*v)
	} else {
		c.logger.Info("failed to add validator")
	}
}

func (c *controller) updateIndices(pubkeys []spec.BLSPubKey) {
	if len(pubkeys) == 0 {
		return
	}
	c.logger.Debug("fetching indices...", zap.Int("total", len(pubkeys)))
	validatorsMap, err := c.beacon.GetIndices(pubkeys)
	if err != nil {
		c.logger.Error("failed to fetch indices", zap.Error(err))
		return
	}
	c.logger.Debug("returned indices from beacon", zap.Int("total", len(validatorsMap)))
	for index, v := range validatorsMap {
		if validator, ok := c.GetValidator(hex.EncodeToString(v.Validator.PublicKey[:])); ok {
			uIndex := uint64(index)
			validator.Share.Index = &uIndex
			err := c.saveValidatorShare(validator.Share)
			if err != nil {
				c.logger.Error("failed to update share index", zap.String("pubkey", validator.Share.PublicKey.SerializeToHexStr()))
				continue
			}
			c.beacon.ExtendIndexMap(index, v.Validator.PublicKey) // updating goClient map
			c.logger.Debug("share index has been updated", zap.String("pubkey", hex.EncodeToString(v.Validator.PublicKey[:])), zap.Any("index", validator.Share.Index))
		}
	}
}

func printValidatorShare(logger *zap.Logger, validatorShare *validatorstorage.Share) {
	var committee []string
	for _, c := range validatorShare.Committee {
		committee = append(committee, fmt.Sprintf(`[IbftId=%d, PK=%x]`, c.IbftId, c.Pk))
	}
	logger.Debug("setup validator",
		zap.String("pubKey", validatorShare.PublicKey.SerializeToHexStr()),
		zap.Uint64("nodeID", validatorShare.NodeID),
		zap.Strings("committee", committee))
}

func (c *controller) getAllValidatorShares() ([]*validatorstorage.Share, error) {
	c.validatorL.RLock()
	defer c.validatorL.RUnlock()
	return c.collection.GetAllValidatorsShare()
}

func (c *controller) getValidatorShare(pk []byte) (*validatorstorage.Share, bool, error) {
	c.validatorL.RLock()
	defer c.validatorL.RUnlock()
	return c.collection.GetValidatorsShare(pk)
}

func (c *controller) saveValidatorShare(share *validatorstorage.Share) error {
	c.validatorL.Lock()
	defer c.validatorL.Unlock()
	return c.collection.SaveValidatorShare(share)
}

// GetValidator returns a validator
func (c *controller) GetValidator(pubKey string) (*Validator, bool) {
	c.validatorL.RLock()
	defer c.validatorL.RUnlock()
	v, ok := c.validatorsMap[pubKey]
	return v, ok
}

// AddValidator adds a new validator
func (c *controller) AddValidator(pubKey string, v *Validator) bool {
	c.validatorL.Lock()
	defer c.validatorL.Unlock()
	if _, ok := c.validatorsMap[pubKey]; !ok {
		c.validatorsMap[pubKey] = v
		return true
	}
	return false
}

// GetValidatorsIndices returns a list of all the active validators indices and fetch indices for missing once (could be first time attesting or non active once)
func (c *controller) GetValidatorsIndices() []spec.ValidatorIndex {
	c.validatorL.RLock()
	defer c.validatorL.RUnlock()

	var indices []spec.ValidatorIndex
	var toFetch []phase0.BLSPubKey
	for _, val := range c.validatorsMap {
		if val.Share.Index == nil {
			blsPubKey := phase0.BLSPubKey{}
			copy(blsPubKey[:], val.Share.PublicKey.Serialize())
			toFetch = append(toFetch, blsPubKey)
		} else {
			index := spec.ValidatorIndex(*val.Share.Index)
			indices = append(indices, index)
		}
	}
	go c.updateIndices(toFetch) // saving missing indices to be ready for next ticker (slot)
	return indices
}

// GetValidatorsPubKeys returns a list of all the validators public keys
func (c *controller) GetValidatorsPubKeys() [][]byte {
	c.validatorL.RLock()
	defer c.validatorL.RUnlock()

	var pubKeys [][]byte
	for _, val := range c.validatorsMap {
		pubKeys = append(pubKeys, val.Share.PublicKey.Serialize())
	}
	return pubKeys
}
