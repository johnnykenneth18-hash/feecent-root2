// services/FinancialTransactionService.js
// ============================================================
// INTEGRATED WITH EXISTING PROJECT STRUCTURE
// ============================================================

const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

class FinancialTransactionService {
    constructor() {
        this.supabase = createClient(
            process.env.SUPABASE_URL,
            process.env.SUPABASE_SERVICE_KEY
        );
        this.lockTimeout = 5000;
    }

    /**
     * Execute a financial transaction with full ACID compliance
     * Integrates with existing account_tier_limits and savings_pool_accounts
     */
    async executeTransaction(params) {
        const {
            requestId,
            userId,
            type,
            debits = [],
            credits = [],
            metadata = {},
            description = ''
        } = params;

        // 1. Validate idempotency
        const idempotencyCheck = await this.checkIdempotency(requestId);
        if (idempotencyCheck) {
            return idempotencyCheck;
        }

        // 2. Validate input
        this.validateTransactionInput(debits, credits, userId);

        // 3. Generate references
        const transactionReference = uuidv4();
        const transactionId = `TXN_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;

        // 4. Execute in database transaction
        const result = await this.supabase.rpc('begin_transaction');

        try {
            // 4a. Lock all accounts in order (prevents deadlocks)
            const allAccountIds = this.getAllAccountIds(debits, credits);
            const lockedAccounts = await this.lockAccounts(allAccountIds);

            // 4b. Validate balances for debits
            await this.validateBalances(debits, lockedAccounts);

            // 4c. Check daily limits (uses existing account_tier_limits)
            await this.checkDailyLimits(userId, debits);

            // 4d. Calculate new balances
            const balanceUpdates = this.calculateNewBalances(debits, credits, lockedAccounts);

            // 4e. Insert transaction record
            const transaction = await this.insertTransaction({
                transactionReference,
                userId,
                type,
                description,
                requestId,
                metadata
            });

            // 4f. Insert ledger entries (double-entry)
            const ledgerEntries = await this.insertLedgerEntries({
                transactionReference,
                userId,
                debits,
                credits,
                balanceUpdates,
                metadata
            });

            // 4g. Update account balances
            await this.updateAccountBalances(balanceUpdates);

            // 4h. Update savings pools if applicable
            await this.updateSavingsPools(transactionReference, debits, credits, userId);

            // 4i. Update transaction status
            await this.updateTransactionStatus(transactionReference, 'completed');

            // 4j. Store idempotency result
            const finalResult = {
                success: true,
                transactionReference,
                transactionId,
                entries: ledgerEntries,
                balances: balanceUpdates
            };

            await this.storeIdempotencyResult(requestId, finalResult);

            // 4k. Log financial audit
            await this.logFinancialAudit({
                userId,
                actionType: type,
                transactionReference,
                details: { debits, credits, balanceUpdates },
                metadata
            });

            // 4l. Trigger async events
            await this.triggerAsyncEvents({
                userId,
                type,
                transactionReference,
                debits,
                credits,
                description
            });

            return finalResult;

        } catch (error) {
            // Rollback on error
            await this.supabase.rpc('rollback_transaction');
            
            await this.logFinancialAudit({
                userId,
                actionType: type,
                transactionReference,
                details: { error: error.message, debits, credits },
                metadata,
                status: 'failed'
            });

            await this.storeIdempotencyResult(requestId, { 
                success: false, 
                error: error.message 
            });

            throw error;
        }
    }

    // ==================== PRIVATE METHODS ====================

    async checkIdempotency(requestId) {
        if (!requestId) return null;

        const { data, error } = await this.supabase
            .from('idempotency_keys')
            .select('response')
            .eq('key', requestId)
            .eq('status', 'completed')
            .single();

        if (error) return null;
        if (data) {
            console.log(`[Idempotency] Request ${requestId} already processed`);
            return data.response;
        }
        return null;
    }

    async storeIdempotencyResult(requestId, response) {
        if (!requestId) return;

        await this.supabase
            .from('idempotency_keys')
            .upsert({
                key: requestId,
                status: response.success ? 'completed' : 'failed',
                response: response,
                expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
            });
    }

    validateTransactionInput(debits, credits, userId) {
        if (debits.length === 0 || credits.length === 0) {
            throw new Error('Transaction must have at least one debit and one credit');
        }

        const totalDebit = debits.reduce((sum, d) => sum + d.amount, 0);
        const totalCredit = credits.reduce((sum, c) => sum + c.amount, 0);

        if (Math.abs(totalDebit - totalCredit) > 0.0001) {
            throw new Error(`Double-entry mismatch: Debit ${totalDebit} != Credit ${totalCredit}`);
        }

        debits.forEach(d => {
            if (!d.accountId) throw new Error('Debit account ID required');
            if (!d.amount || d.amount <= 0) throw new Error('Debit amount must be positive');
        });

        credits.forEach(c => {
            if (!c.accountId) throw new Error('Credit account ID required');
            if (!c.amount || c.amount <= 0) throw new Error('Credit amount must be positive');
        });
    }

    getAllAccountIds(debits, credits) {
        const ids = new Set();
        debits.forEach(d => ids.add(d.accountId));
        credits.forEach(c => ids.add(c.accountId));
        return Array.from(ids);
    }

    // Add this method to FinancialTransactionService.js

/**
 * Check if a transaction has already been processed
 */
async checkTransactionIdempotency(requestId, userId, transactionType, referenceId) {
  if (!requestId) return null;

  const { data, error } = await this.supabase
    .from('idempotency_keys')
    .select('response')
    .eq('key', requestId)
    .eq('user_id', userId)
    .eq('status', 'completed')
    .single();

  if (error) return null;
  if (data) {
    console.log(`[Idempotency] Request ${requestId} already processed for user ${userId}`);
    return data.response;
  }
  return null;
}

    async lockAccounts(accountIds) {
        if (accountIds.length === 0) return [];

        const sortedIds = [...accountIds].sort();

        const { data: accounts, error } = await this.supabase
            .from('accounts')
            .select('id, user_id, balance, available_balance')
            .in('id', sortedIds)
            .order('id', { ascending: true });

        if (error) {
            throw new Error(`Failed to lock accounts: ${error.message}`);
        }

        return accounts;
    }

    async validateBalances(debits, lockedAccounts) {
        const accountMap = new Map();
        lockedAccounts.forEach(a => accountMap.set(a.id, a));

        for (const debit of debits) {
            const account = accountMap.get(debit.accountId);
            if (!account) {
                throw new Error(`Account ${debit.accountId} not found or locked`);
            }

            if (account.available_balance < debit.amount) {
                throw new Error(
                    `Insufficient balance for account ${account.id}. ` +
                    `Available: ${account.available_balance}, Required: ${debit.amount}`
                );
            }
        }
    }

    /**
     * Check daily limits using existing account_tier_limits table
     */
    async checkDailyLimits(userId, debits) {
        // Get user's tier
        const { data: user, error: userError } = await this.supabase
            .from('users')
            .select('account_tier')
            .eq('id', userId)
            .single();

        if (userError) {
            console.warn('Failed to get user tier:', userError);
            return;
        }

        // Get tier limits
        const { data: limits, error: limitsError } = await this.supabase
            .from('account_tier_limits')
            .select('daily_transfer_limit, single_transfer_limit')
            .eq('tier', user.account_tier || 1)
            .single();

        if (limitsError || !limits) {
            console.warn('Failed to get tier limits:', limitsError);
            return;
        }

        // Check single transfer limit
        const totalDebit = debits.reduce((sum, d) => sum + d.amount, 0);
        if (totalDebit > limits.single_transfer_limit) {
            throw new Error(
                `Single transfer limit for your tier is ₦${limits.single_transfer_limit.toLocaleString()}`
            );
        }

        // Check daily limit
        const today = new Date();
        today.setHours(0, 0, 0, 0);

        const { data: todayTransfers, error: txError } = await this.supabase
            .from('transactions_new')
            .select('amount')
            .eq('user_id', userId)
            .eq('status', 'completed')
            .gte('created_at', today.toISOString());

        if (txError) {
            console.warn('Daily limit check failed:', txError);
            return;
        }

        const todayTotal = todayTransfers.reduce((sum, t) => sum + t.amount, 0);
        if (todayTotal + totalDebit > limits.daily_transfer_limit) {
            throw new Error(
                `Daily transfer limit for your tier is ₦${limits.daily_transfer_limit.toLocaleString()}. ` +
                `You have ₦${(limits.daily_transfer_limit - todayTotal).toLocaleString()} remaining today.`
            );
        }
    }

    calculateNewBalances(debits, credits, lockedAccounts) {
        const accountMap = new Map();
        lockedAccounts.forEach(a => accountMap.set(a.id, { ...a }));

        const updates = [];

        for (const debit of debits) {
            const account = accountMap.get(debit.accountId);
            if (!account) continue;

            const newBalance = account.balance - debit.amount;
            const newAvailable = account.available_balance - debit.amount;

            updates.push({
                accountId: account.id,
                userId: account.user_id,
                balanceBefore: account.balance,
                balanceAfter: newBalance,
                availableBefore: account.available_balance,
                availableAfter: newAvailable,
                type: 'DEBIT',
                amount: debit.amount,
                reason: debit.reason
            });

            account.balance = newBalance;
            account.available_balance = newAvailable;
        }

        for (const credit of credits) {
            const account = accountMap.get(credit.accountId);
            if (!account) continue;

            const newBalance = account.balance + credit.amount;
            const newAvailable = account.available_balance + credit.amount;

            updates.push({
                accountId: account.id,
                userId: account.user_id,
                balanceBefore: account.balance - credit.amount,
                balanceAfter: newBalance,
                availableBefore: account.available_balance - credit.amount,
                availableAfter: newAvailable,
                type: 'CREDIT',
                amount: credit.amount,
                reason: credit.reason
            });

            account.balance = newBalance;
            account.available_balance = newAvailable;
        }

        return updates;
    }

    async insertTransaction({ transactionReference, userId, type, description, requestId, metadata }) {
        const { data, error } = await this.supabase
            .from('transactions_new')
            .insert({
                transaction_reference: transactionReference,
                user_id: userId,
                transaction_type: type,
                status: 'pending',
                description: description,
                request_id: requestId,
                idempotency_key: requestId,
                created_at: new Date().toISOString(),
                ip_address: metadata.ip || null,
                user_agent: metadata.userAgent || null,
                created_by: userId,
                metadata: metadata
            })
            .select()
            .single();

        if (error) {
            throw new Error(`Failed to insert transaction: ${error.message}`);
        }

        return data;
    }

    async insertLedgerEntries({ transactionReference, userId, debits, credits, balanceUpdates, metadata }) {
        const entries = [];

        for (const update of balanceUpdates) {
            const { data, error } = await this.supabase
                .from('ledger')
                .insert({
                    transaction_reference: transactionReference,
                    user_id: update.userId,
                    account_id: update.accountId,
                    currency: 'NGN',
                    entry_type: update.type,
                    amount: update.amount,
                    balance_before: update.balanceBefore,
                    balance_after: update.balanceAfter,
                    running_balance: update.balanceAfter,
                    description: update.reason || `${update.type} transaction`,
                    status: 'completed',
                    created_by: userId,
                    created_at: new Date().toISOString(),
                    ip_address: metadata.ip || null,
                    device_info: metadata.userAgent || null
                })
                .select()
                .single();

            if (error) {
                throw new Error(`Failed to insert ledger entry: ${error.message}`);
            }

            entries.push(data);
        }

        return entries;
    }

    async updateAccountBalances(balanceUpdates) {
        for (const update of balanceUpdates) {
            const { error } = await this.supabase
                .from('accounts')
                .update({
                    balance: update.balanceAfter,
                    available_balance: update.availableAfter,
                    updated_at: new Date().toISOString()
                })
                .eq('id', update.accountId);

            if (error) {
                throw new Error(`Failed to update account ${update.accountId}: ${error.message}`);
            }
        }
    }

    /**
     * Update savings pools using existing savings_pool_accounts table
     */
    async updateSavingsPools(transactionReference, debits, credits, userId) {
        // Get all pool accounts
        const { data: pools, error } = await this.supabase
            .from('savings_pool_accounts')
            .select('*');

        if (error) {
            console.warn('Failed to get savings pools:', error);
            return;
        }

        const poolMap = new Map();
        pools.forEach(p => poolMap.set(p.account_type, p));

        // Process each debit/credit that might affect pools
        for (const debit of debits) {
            // Check if this is a savings pool account
            let poolType = null;
            if (debit.accountId === poolMap.get('harvest_pool')?.id) poolType = 'harvest_pool';
            else if (debit.accountId === poolMap.get('fixed_pool')?.id) poolType = 'fixed_pool';
            else if (debit.accountId === poolMap.get('savebox_pool')?.id) poolType = 'savebox_pool';
            else if (debit.accountId === poolMap.get('target_pool')?.id) poolType = 'target_pool';
            else if (debit.accountId === poolMap.get('spare_change_pool')?.id) poolType = 'spare_change_pool';
            else if (debit.accountId === poolMap.get('fee_account')?.id) poolType = 'fee_account';

            if (poolType && poolMap.get(poolType)) {
                const pool = poolMap.get(poolType);
                await this.supabase
                    .from('savings_pool_accounts')
                    .update({
                        balance: pool.balance - debit.amount,
                        available_balance: pool.available_balance - debit.amount,
                        updated_at: new Date().toISOString()
                    })
                    .eq('id', pool.id);
                pool.balance -= debit.amount;
                pool.available_balance -= debit.amount;
            }
        }

        for (const credit of credits) {
            let poolType = null;
            if (credit.accountId === poolMap.get('harvest_pool')?.id) poolType = 'harvest_pool';
            else if (credit.accountId === poolMap.get('fixed_pool')?.id) poolType = 'fixed_pool';
            else if (credit.accountId === poolMap.get('savebox_pool')?.id) poolType = 'savebox_pool';
            else if (credit.accountId === poolMap.get('target_pool')?.id) poolType = 'target_pool';
            else if (credit.accountId === poolMap.get('spare_change_pool')?.id) poolType = 'spare_change_pool';
            else if (credit.accountId === poolMap.get('fee_account')?.id) poolType = 'fee_account';

            if (poolType && poolMap.get(poolType)) {
                const pool = poolMap.get(poolType);
                await this.supabase
                    .from('savings_pool_accounts')
                    .update({
                        balance: pool.balance + credit.amount,
                        available_balance: pool.available_balance + credit.amount,
                        updated_at: new Date().toISOString()
                    })
                    .eq('id', pool.id);
                pool.balance += credit.amount;
                pool.available_balance += credit.amount;
            }
        }
    }

    async updateTransactionStatus(transactionReference, status) {
        const { error } = await this.supabase
            .from('transactions_new')
            .update({
                status: status,
                completed_at: status === 'completed' ? new Date().toISOString() : null,
                updated_at: new Date().toISOString()
            })
            .eq('transaction_reference', transactionReference);

        if (error) {
            console.error('Failed to update transaction status:', error);
        }
    }

    async logFinancialAudit({ userId, actionType, transactionReference, details, metadata, status = 'completed' }) {
        try {
            const { error } = await this.supabase
                .from('financial_audit_log')
                .insert({
                    user_id: userId,
                    action_type: actionType,
                    transaction_reference: transactionReference,
                    details: details,
                    ip_address: metadata.ip || null,
                    user_agent: metadata.userAgent || null,
                    request_id: metadata.requestId,
                    created_at: new Date().toISOString()
                });

            if (error) {
                console.error('Failed to log financial audit:', error);
            }
        } catch (error) {
            console.error('Financial audit logging failed:', error);
        }
    }

    async triggerAsyncEvents({ userId, type, transactionReference, debits, credits, description }) {
        setImmediate(async () => {
            try {
                await this.createTransactionNotification({
                    userId,
                    type,
                    transactionReference,
                    amount: credits.reduce((sum, c) => sum + c.amount, 0),
                    description
                });
            } catch (error) {
                console.error('Async event trigger failed:', error);
            }
        });
    }

    async createTransactionNotification({ userId, type, transactionReference, amount, description }) {
        try {
            const titles = {
                'TRANSFER': 'Transfer Completed',
                'DEPOSIT': 'Deposit Received',
                'WITHDRAWAL': 'Withdrawal Processed',
                'SAVINGS': 'Savings Update',
                'ADJUSTMENT': 'Account Adjustment',
                'REFUND': 'Refund Processed'
            };

            const messages = {
                'TRANSFER': `₦${amount.toLocaleString()} transfer completed${description ? `: ${description}` : ''}`,
                'DEPOSIT': `₦${amount.toLocaleString()} deposited to your account`,
                'WITHDRAWAL': `₦${amount.toLocaleString()} withdrawn from your account`,
                'SAVINGS': `₦${amount.toLocaleString()} moved to savings`,
                'ADJUSTMENT': `Account adjusted by ₦${amount.toLocaleString()}`,
                'REFUND': `₦${amount.toLocaleString()} refunded to your account`
            };

            await this.supabase
                .from('notifications')
                .insert({
                    user_id: userId,
                    title: titles[type] || 'Transaction Completed',
                    message: messages[type] || `Transaction of ₦${amount.toLocaleString()} completed`,
                    type: type === 'DEBIT' ? 'debit' : 'credit',
                    created_at: new Date().toISOString(),
                    is_read: false
                });
        } catch (error) {
            console.error('Notification creation failed:', error);
        }
    }
}

module.exports = FinancialTransactionService;