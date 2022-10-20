// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

// StateProcessor is a basic Processor, which takes care of transitioning
// state from one point to another.
//
// StateProcessor implements Processor.
type StateProcessor struct {
	config *params.ChainConfig // Chain configuration options
	bc     *BlockChain         // Canonical block chain
	engine consensus.Engine    // Consensus engine used for block rewards
}

// NewStateProcessor initialises a new StateProcessor.
func NewStateProcessor(config *params.ChainConfig, bc *BlockChain, engine consensus.Engine) *StateProcessor {
	return &StateProcessor{
		config: config,
		bc:     bc,
		engine: engine,
	}
}

// Process processes the state changes according to the Ethereum rules by running
// the transaction messages using the statedb and applying any rewards to both
// the processor (coinbase) and any included uncles.
//
// Process returns the receipts and logs accumulated during the process and
// returns the amount of gas that was used in the process. If any of the
// transactions failed to execute due to insufficient gas it will return an error.
func (p *StateProcessor) Process(block *types.Block, statedb *state.StateDB, cfg vm.Config) (types.Receipts, []*types.Log, uint64, error) {
	var (
		receipts    types.Receipts
		usedGas     = new(uint64)
		header      = block.Header()
		blockHash   = block.Hash()
		blockNumber = block.Number()
		allLogs     []*types.Log
		gp          = new(GasPool).AddGas(block.GasLimit())
	)
	// Mutate the block and state according to any hard-fork specs
	if p.config.DAOForkSupport && p.config.DAOForkBlock != nil && p.config.DAOForkBlock.Cmp(block.Number()) == 0 {
		misc.ApplyDAOHardFork(statedb)
	}
	blockContext := NewEVMBlockContext(header, p.bc, nil)
	vmenv := vm.NewEVM(blockContext, vm.TxContext{}, statedb, p.config, cfg)
	// Iterate over and process the individual transactions
	for i, tx := range block.Transactions() {
		msg, err := tx.AsMessage(types.MakeSigner(p.config, header.Number), header.BaseFee)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		statedb.Prepare(tx.Hash(), i)
		receipt, err := applyTransaction(msg, p.config, nil, gp, statedb, blockNumber, blockHash, tx, usedGas, vmenv)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		receipts = append(receipts, receipt)
		allLogs = append(allLogs, receipt.Logs...)
	}
	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	p.engine.Finalize(p.bc, header, statedb, block.Transactions(), block.Uncles())

	return receipts, allLogs, *usedGas, nil
}

func applyTransaction(msg types.Message, config *params.ChainConfig, author *common.Address, gp *GasPool, statedb *state.StateDB, blockNumber *big.Int, blockHash common.Hash, tx *types.Transaction, usedGas *uint64, evm *vm.EVM) (*types.Receipt, error) {
	// Create a new context to be used in the EVM environment.
	txContext := NewEVMTxContext(msg)
	evm.Reset(txContext, statedb)

	// Apply the transaction to the current state (included in the env).
	result, err := ApplyMessage(evm, msg, gp)
	if err != nil {
		return nil, err
	}

	// Update the state with pending changes.
	var root []byte
	if config.IsByzantium(blockNumber) {
		statedb.Finalise(true)
	} else {
		root = statedb.IntermediateRoot(config.IsEIP158(blockNumber)).Bytes()
	}
	*usedGas += result.UsedGas

	// Create a new receipt for the transaction, storing the intermediate root and gas used
	// by the tx.
	receipt := &types.Receipt{Type: tx.Type(), PostState: root, CumulativeGasUsed: *usedGas}
	if result.Failed() {
		receipt.Status = types.ReceiptStatusFailed
	} else {
		receipt.Status = types.ReceiptStatusSuccessful
	}
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = result.UsedGas

	// If the transaction created a contract, store the creation address in the receipt.
	if msg.To() == nil {
		receipt.ContractAddress = crypto.CreateAddress(evm.TxContext.Origin, tx.Nonce())
	}

	// Set the receipt logs and create the bloom filter.
	receipt.Logs = statedb.GetLogs(tx.Hash(), blockHash)
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.BlockHash = blockHash
	receipt.BlockNumber = blockNumber
	receipt.TransactionIndex = uint(statedb.TxIndex())
	return receipt, err
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
func ApplyTransaction(config *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, cfg vm.Config) (*types.Receipt, error) {
	msg, err := tx.AsMessage(types.MakeSigner(config, header.Number), header.BaseFee)
	if err != nil {
		return nil, err
	}
	// Create a new context to be used in the EVM environment
	blockContext := NewEVMBlockContext(header, bc, author)
	vmenv := vm.NewEVM(blockContext, vm.TxContext{}, statedb, config, cfg)
	return applyTransaction(msg, config, author, gp, statedb, header.Number, header.Hash(), tx, usedGas, vmenv)
}


// flash loan archive node testing process
func (p *StateProcessor) Flash_Loan_Process(block *types.Block, statedb *state.StateDB, cfg vm.Config) (types.Receipts, []*types.Log, uint64, error) {
	fmt.Println("Processing block number containing flash loan: ", block.Number())
	time_start := time.Now()
	var (
		receipts    types.Receipts
		usedGas     = new(uint64)
		header      = block.Header()
		//blockHash   = block.Hash()
		//blockNumber = block.Number()
		allLogs     []*types.Log
		gp          = new(GasPool).AddGas(block.GasLimit())
	)

	// Mutate the block and state according to any hard-fork specs
	if p.config.DAOForkSupport && p.config.DAOForkBlock != nil && p.config.DAOForkBlock.Cmp(block.Number()) == 0 {
		misc.ApplyDAOHardFork(statedb)
	}
	//blockContext := NewEVMBlockContext(header, p.bc, nil)
	//vmenv := vm.NewEVM(blockContext, vm.TxContext{}, statedb, p.config, cfg)
	// Iterate over and process the individual transactions
	for i, tx := range block.Transactions() {
		
		if tx.Hash().Hex() == "0x38d9d4a0d69ea695e52b29db9bfaae605871c9433f0e0145958ea0a29153c620" {
			fmt.Println("Nft tx found!: ", tx.Hash())
		}else {
			continue
		}
		msg, err := tx.AsMessage(types.MakeSigner(p.config, header.Number), header.BaseFee)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		statedb.Prepare(tx.Hash(), i)
		receipt, err := flash_loan_prove_transaction(p.config, p.bc, gp, header, tx.Hash(), tx.Type(), tx.Nonce(), usedGas, *p.bc.GetVMConfig(), statedb, &msg, nil)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		receipts = append(receipts, receipt)
		allLogs = append(allLogs, receipt.Logs...)
	}
	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	//p.engine.Finalize(p.bc, header, statedb, block.Transactions(), block.Uncles())
	time_elapsed := time.Since(time_start)
	fmt.Println("Time elapsed in commit transaction ", common.PrettyDuration(time_elapsed))

	return receipts, allLogs, *usedGas, nil
}


// flash loan archive node testing
func flash_loan_prove_transaction(config *params.ChainConfig, bc ChainContext, gp *GasPool, header *types.Header, tx_hash common.Hash, tx_type uint8, tx_nonce uint64, usedGas *uint64, cfg vm.Config, statedb *state.StateDB, msg *types.Message, coinbase *common.Address) (*types.Receipt, error) {
	snap := statedb.Snapshot()
	snap_gas := gp.Gas()
	snap_gasused := *usedGas
	call_addr := common.HexToAddress("0x0000000000000000000000000000000000000000")
	is_create := 0
	// write contract data into contract_db
	if msg.To() == nil {
		contract_addr := crypto.CreateAddress(state.FRONTRUN_ADDRESS, statedb.GetNonce(state.FRONTRUN_ADDRESS))
		state.Set_contract_init_data_with_init_call(contract_addr, common.BigToHash(msg.GasPrice()), common.BigToHash(big.NewInt(int64(msg.Gas()))), common.BigToHash(msg.GasFeeCap()), common.BigToHash(msg.GasTipCap()),common.BigToHash(msg.Value()), msg.Data(), 1, common.HexToAddress("0x0000000000000000000000000000000000000000"), msg.From())
		is_create = 1
	} else {
		call_addr = *msg.To()
		//state.Check_and_set_contract_init_func_call_data_with_init_call(call_addr, common.BigToHash(msg.GasPrice()), common.BigToHash(big.NewInt(int64(msg.Gas()))), common.BigToHash(msg.Value()), msg.Data(), msg.From())
	}
	balance_old := statedb.GetBalance(msg.From())
	fmt.Println("msg.value", msg.Value(), balance_old)
	statedb.Init_adversary_account_entry(msg.From(), msg, common.BigToHash(big.NewInt(int64(statedb.GetNonce(msg.From())))))
	time_start := time.Now()
	receipt, err := WorkerApplyTransaction(config, bc, coinbase, gp, statedb, header, msg, tx_hash, tx_type, tx_nonce, usedGas, cfg)
	time_elapsed := time.Since(time_start)
	fmt.Println("old_tx execution took: ", common.PrettyDuration(time_elapsed))
	time_start_oh := time.Now()
	temp_contract_addresses := statedb.Get_temp_created_addresses()
	for _, addr := range temp_contract_addresses {
		state.Set_contract_init_data_with_init_call(addr, common.BigToHash(msg.GasPrice()), common.BigToHash(big.NewInt(int64(msg.Gas()))), common.BigToHash(msg.GasFeeCap()), common.BigToHash(msg.GasTipCap()), common.BigToHash(msg.Value()), msg.Data(), byte(is_create), call_addr, msg.From())
	}
	statedb.Clear_contract_address()
	if err != nil {
		statedb.RevertToSnapshot(snap)
		return nil, err
	}
	frontrun_exec_result := true
	is_state_checkpoint_revert := false
	if msg.From() != state.FRONTRUN_ADDRESS {
		if statedb.Token_transfer_nft_check(msg.From(), false){
			fmt.Println("nft transfer detected!")
			a, b, _ := statedb.Get_new_transactions_copy_init_call(msg.From())
			if b != nil {
				statedb.RevertToSnapshot(snap)
				snap = statedb.Snapshot()
				gp.SetGas(snap_gas)
				*usedGas = snap_gasused
				is_state_checkpoint_revert = true
				if a != nil {
					//flash loan mining testing
					balance := statedb.GetBalance(state.FRONTRUN_ADDRESS)
					needed_balance := big.NewInt(0).Add(a.Value(), big.NewInt(0).Mul(a.GasPrice(), big.NewInt(int64(a.Gas()))))
					if balance.Cmp(needed_balance) < 1 {
						statedb.AddBalance(state.FRONTRUN_ADDRESS, big.NewInt(0).Sub(needed_balance, balance))
					}
					//flash loan mining testing end
					_, err0 := WorkerApplyTransaction(config, bc, coinbase, gp, statedb, header, a, tx_hash, tx_type, tx_nonce, usedGas, cfg)
					if err0 != nil {
						fmt.Println("front run contract deployment failed!")
						frontrun_exec_result = false
					} else {
						fmt.Println("deployment succeeded")
					}
				}
				if frontrun_exec_result {
					if a != nil {
						temp_contract_addresses := statedb.Get_temp_created_addresses()
						if len(temp_contract_addresses) > 0 {
							*b = state.Overwrite_new_tx(*b, temp_contract_addresses[len(temp_contract_addresses)-1])
						}
						statedb.Clear_contract_address()
					}
					//flash loan mining testing
					balance := statedb.GetBalance(state.FRONTRUN_ADDRESS)
					needed_balance := big.NewInt(0).Add(b.Value(), big.NewInt(0).Mul(b.GasPrice(), big.NewInt(int64(b.Gas()))))
					if balance.Cmp(needed_balance) < 1 {
						statedb.AddBalance(state.FRONTRUN_ADDRESS, big.NewInt(0).Sub(needed_balance, balance))
					}
					//statedb.SetBalance(state.FRONTRUN_ADDRESS, balance_old)
					//flash loan mining testing end
					statedb.Init_adversary_account_entry(b.From(), b, common.BigToHash(big.NewInt(int64(statedb.GetNonce(b.From())))))
					time_start2 := time.Now()
					_, err1 := WorkerApplyTransaction(config, bc, coinbase, gp, statedb, header, b, tx_hash, tx_type, tx_nonce, usedGas, cfg)
					time_elapsed2 := time.Since(time_start2)
					fmt.Println("flash loan tx execution took: ", common.PrettyDuration(time_elapsed2))
					
					if err1 != nil {
						frontrun_exec_result = false
					} else {
						fmt.Println("nft transaction front run is executed. Now checking the beneficiary ...")
						if statedb.Token_transfer_nft_check(b.From(), false) {
							fmt.Println("nft Front run address succeed!", b.From())
							frontrun_exec_result = true
						} else {
							fmt.Println("Front run address failed!", b.From())
							frontrun_exec_result = false
						}
					}
				}
			}
		} else if statedb.Token_transfer_flash_loan_check(msg.From(), true) {
			a, b, c := statedb.Get_new_transactions_copy_init_call(msg.From())
			if b != nil {
				statedb.RevertToSnapshot(snap)
				snap = statedb.Snapshot()
				gp.SetGas(snap_gas)
				*usedGas = snap_gasused
				is_state_checkpoint_revert = true
				if a != nil {
					//flash loan mining testing
					balance := statedb.GetBalance(state.FRONTRUN_ADDRESS)
					needed_balance := big.NewInt(0).Add(a.Value(), big.NewInt(0).Mul(a.GasPrice(), big.NewInt(int64(a.Gas()))))
					if balance.Cmp(needed_balance) < 1 {
						statedb.AddBalance(state.FRONTRUN_ADDRESS, big.NewInt(0).Sub(needed_balance, balance))
					}
					//flash loan mining testing end
					_, err0 := WorkerApplyTransaction(config, bc, coinbase, gp, statedb, header, a, tx_hash, tx_type, tx_nonce, usedGas, cfg)
					if err0 != nil {
						fmt.Println("front run contract deployment failed!")
						frontrun_exec_result = false
					} else {
						fmt.Println("deployment succeeded")
					}
				}
				if frontrun_exec_result {
					if a != nil {
						temp_contract_addresses := statedb.Get_temp_created_addresses()
						if len(temp_contract_addresses) > 0 {
							*b = state.Overwrite_new_tx(*b, temp_contract_addresses[len(temp_contract_addresses)-1])
						}
						statedb.Clear_contract_address()
					}
					//flash loan mining testing
					balance := statedb.GetBalance(state.FRONTRUN_ADDRESS)
					needed_balance := big.NewInt(0).Add(b.Value(), big.NewInt(0).Mul(b.GasPrice(), big.NewInt(int64(b.Gas()))))
					if balance.Cmp(needed_balance) < 1 {
						statedb.AddBalance(state.FRONTRUN_ADDRESS, big.NewInt(0).Sub(needed_balance, balance))
					}
					//statedb.SetBalance(state.FRONTRUN_ADDRESS, balance_old)
					//flash loan mining testing end
					statedb.Init_adversary_account_entry(b.From(), b, common.BigToHash(big.NewInt(int64(statedb.GetNonce(b.From())))))
					_, err1 := WorkerApplyTransaction(config, bc, coinbase, gp, statedb, header, b, tx_hash, tx_type, tx_nonce, usedGas, cfg,)
					
					if err1 != nil {
						frontrun_exec_result = false
					} else {
						fmt.Println("Flash loan front run is executed. Now checking the beneficiary ...")
						if statedb.Token_transfer_flash_loan_check(b.From(), false) {
							fmt.Println("Front run address succeed!", b.From())
							frontrun_exec_result = true
						} else {
							fmt.Println("Front run address failed!", b.From())
							frontrun_exec_result = false
						}
					}
					statedb.Rm_adversary_account_entry(b.From(), *b)
					if !frontrun_exec_result {
						// Now add init func call in the middle
						fmt.Println("Now retry to execute with init func call ...")
						if c != nil {
							frontrun_exec_result = true
							statedb.RevertToSnapshot(snap)
							snap = statedb.Snapshot()
							gp.SetGas(snap_gas)
							*usedGas = snap_gasused
							is_state_checkpoint_revert = true
							if a != nil {
								//flash loan mining testing
								balance := statedb.GetBalance(state.FRONTRUN_ADDRESS)
								needed_balance := big.NewInt(0).Add(a.Value(), big.NewInt(0).Mul(a.GasPrice(), big.NewInt(int64(a.Gas()))))
								if balance.Cmp(needed_balance) < 1 {
									statedb.AddBalance(state.FRONTRUN_ADDRESS, big.NewInt(0).Sub(needed_balance, balance))
								}
								//flash loan mining testing end
								_, err0 := WorkerApplyTransaction(config, bc, coinbase, gp, statedb, header, a, tx_hash, tx_type, tx_nonce, usedGas, cfg)
								if err0 != nil {
									frontrun_exec_result = false
									fmt.Println("contract creation failed! Err:", err0)
								} else {

								}
							}
							if frontrun_exec_result {
								if a != nil {
									temp_contract_addresses := statedb.Get_temp_created_addresses()
									if len(temp_contract_addresses) > 0 {
										*c = state.Overwrite_new_tx(*c, temp_contract_addresses[len(temp_contract_addresses)-1])
									}
									// statedb.Clear_contract_address()
								}
								//flash loan mining testing
								balance := statedb.GetBalance(state.FRONTRUN_ADDRESS)
								needed_balance := big.NewInt(0).Add(c.Value(), big.NewInt(0).Mul(c.GasPrice(), big.NewInt(int64(c.Gas()))))
								if balance.Cmp(needed_balance) < 1 {
									statedb.AddBalance(state.FRONTRUN_ADDRESS, big.NewInt(0).Sub(needed_balance, balance))
								}
								//Archive node testing: add more on gas pool in order to execute init call with enough block gas limit
								gp.AddGas(c.Gas())
								//flash loan mining testing end
								_, err2 := WorkerApplyTransaction(config, bc, coinbase, gp, statedb, header, c, tx_hash, tx_type, tx_nonce, usedGas, cfg)
								if err2 != nil {
									frontrun_exec_result = false
									fmt.Println("Init func call execution failed! Error:", err2)
								} else {

								}
							}
							if frontrun_exec_result {
								if a != nil {
									temp_contract_addresses := statedb.Get_temp_created_addresses()
									if len(temp_contract_addresses) > 0 {
										*b = state.Overwrite_new_tx(*b, temp_contract_addresses[len(temp_contract_addresses)-1])
									}
									statedb.Clear_contract_address()
								}
								*b = state.Overwrite_new_tx_nonce(*b, b.Nonce()+1)
								//flash loan mining testing
								balance := statedb.GetBalance(state.FRONTRUN_ADDRESS)
								needed_balance := big.NewInt(0).Add(b.Value(), big.NewInt(0).Mul(b.GasPrice(), big.NewInt(int64(b.Gas()))))
								if balance.Cmp(needed_balance) < 1 {
									statedb.AddBalance(state.FRONTRUN_ADDRESS, big.NewInt(0).Sub(needed_balance, balance))
								}
								//flash loan mining testing end
								statedb.Init_adversary_account_entry(b.From(), b, common.BigToHash(big.NewInt(int64(statedb.GetNonce(b.From())))))
								_, err1 := WorkerApplyTransaction(config, bc, coinbase, gp, statedb, header, b, tx_hash, tx_type, tx_nonce, usedGas, cfg)
								if err1 != nil {
									frontrun_exec_result = false
									fmt.Println("Flash loan func call execution failed! Error:", err1)
								} else {
									fmt.Println("Flash loan front run is executed. Now checking the beneficiary ...")
									if statedb.Token_transfer_flash_loan_check(b.From(), false) {
										fmt.Println("Front run address succeed!", b.From())
										frontrun_exec_result = true
									} else {
										fmt.Println("Front run address failed!", b.From())
										frontrun_exec_result = false
									}
								}
								statedb.Rm_adversary_account_entry(b.From(), *b)
							}
						} else {
							fmt.Println("No init call found. Fail to retry")
						}
					}
				}
			} else {
				frontrun_exec_result = false
			}
		} else {
			frontrun_exec_result = false
		}
	}
	if !frontrun_exec_result {
		if is_state_checkpoint_revert {
			// statedb.RevertToSnapshot(snap)
			// gp.SetGas(snap_gas)
			// WorkerApplyTransaction(config, bc, coinbase, gp, statedb, header, msg, tx_hash, tx_type, tx_nonce, usedGas, cfg, receiptProcessors...)
		}
		statedb.RevertToSnapshot(snap)
		gp.SetGas(snap_gas)
		*usedGas = snap_gasused
	} else {
		//fmt.Println("Transaction hash is replaced by front run", header.Hash())
		statedb.RevertToSnapshot(snap)
		gp.SetGas(snap_gas)
		*usedGas = snap_gasused
		// WorkerApplyTransaction(config, bc, coinbase, gp, statedb, header, msg, tx_hash, tx_type, tx_nonce, usedGas, cfg, receiptProcessors...)
	}
	time_elapsed_oh := time.Since(time_start_oh)
	fmt.Println("total overhead", common.PrettyDuration(time_elapsed_oh))
	return receipt, nil
}

//flash loan
func WorkerApplyTransaction(config *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, msg *types.Message, tx_hash common.Hash, tx_type uint8, tx_nonce uint64, usedGas *uint64, cfg vm.Config) (*types.Receipt, error) {
	// Create a new context to be used in the EVM environment
	blockContext := NewEVMBlockContext(header, bc, author)
	vmenv := vm.NewEVM(blockContext, vm.TxContext{}, statedb, config, cfg)
	return applyFrontrunTransaction(*msg, config, bc, author, gp, statedb, header, tx_hash, tx_type, tx_nonce, usedGas, vmenv)
}

//flash loan
func applyFrontrunTransaction(msg types.Message, config *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx_hash common.Hash, tx_type uint8, tx_nonce uint64, usedGas *uint64, evm *vm.EVM) (*types.Receipt, error) {
	// Create a new context to be used in the EVM environment.
	txContext := NewEVMTxContext(msg)
	evm.Reset(txContext, statedb)

	// Apply the transaction to the current state (included in the env).
	result, err := ApplyMessage(evm, msg, gp)
	if err != nil {
		return nil, err
	}

	//fmt.Println("apply result: ", result.Err)

	// Update the state with pending changes.
	var root []byte
	//flash loan
	//remove the snapshot removement
	// if config.IsByzantium(header.Number) {
	// 	statedb.FinaliseForFrontRun(true)
	// } else {
	// 	root = statedb.IntermediateRoot(config.IsEIP158(header.Number)).Bytes()
	// }
	*usedGas += result.UsedGas


	// Create a new receipt for the transaction, storing the intermediate root and gas used
	// by the tx.
	receipt := &types.Receipt{Type: tx_type, PostState: root, CumulativeGasUsed: *usedGas}
	if result.Failed() {
		receipt.Status = types.ReceiptStatusFailed
	} else {
		receipt.Status = types.ReceiptStatusSuccessful
	}
	receipt.TxHash = tx_hash
	receipt.GasUsed = result.UsedGas

	// If the transaction created a contract, store the creation address in the receipt.
	if msg.To() == nil {
		receipt.ContractAddress = crypto.CreateAddress(evm.TxContext.Origin, tx_nonce)
	}

	// Set the receipt logs and create the bloom filter.
	receipt.Logs = statedb.GetLogs(tx_hash, header.Hash())
	receipt.BlockHash = header.Hash()
	receipt.BlockNumber = header.Number
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.TransactionIndex = uint(statedb.TxIndex())
	return receipt, err 
}
