#######################################
# Dispatches native transfers to a test net.
# Arguments:
#   Network ordinal identifier.
#   Node ordinal identifier.
#   Transfer amount.
#   User ordinal identifier.
#   Count of transfers to be dispatched.
#   Transfer dispatch interval.
#   Gas price.
#   Gas payment.
#######################################
function do_transfer_native()
{
    local NET_ID=${1}
    local NODE_ID=${2}
    local AMOUNT=${3}
    local USER_ID=${4}
    local TRANSFERS=${5}
    local TRANSFER_INTERVAL=${6}
    local GAS=${7}
    local PAYMENT=${8}

    local CHAIN_NAME=$(get_chain_name $NET_ID)
    local CP1_SECRET_KEY=$(get_path_to_secret_key $NET_ID $NCTL_ACCOUNT_TYPE_FAUCET)
    local CP1_PUBLIC_KEY=$(get_account_key $NET_ID $NCTL_ACCOUNT_TYPE_FAUCET)
    local CP2_PUBLIC_KEY=$(get_account_key $NET_ID $NCTL_ACCOUNT_TYPE_USER $USER_ID)
    local PATH_TO_CLIENT=$(get_path_to_client $NET_ID)

    log "dispatching $TRANSFERS native transfers"
    log "... network=$NET_ID"
    log "... node=$NODE_ID"
    log "... transfer amount=$AMOUNT"
    log "... transfer interval=$TRANSFER_INTERVAL (s)"
    log "... counter-party 1 public key=$CP1_PUBLIC_KEY"
    log "... counter-party 2 public key=$CP2_PUBLIC_KEY"
    log "... dispatched deploys:"

    function _dispatch_deploy {
        echo $(
            $PATH_TO_CLIENT transfer \
                --chain-name $CHAIN_NAME \
                --gas-price $GAS \
                --node-address $(get_node_address_rpc $NET_ID $NODE_ID) \
                --payment-amount $PAYMENT \
                --secret-key $CP1_SECRET_KEY \
                --ttl "1day" \
                --amount $AMOUNT \
                --target-account $CP2_PUBLIC_KEY \
                | jq '.result.deploy_hash' \
                | sed -e 's/^"//' -e 's/"$//'
            )
    }

    # Round robin dispatch.
    if [ $NODE_ID = "all" ]; then
        local COUNT_OF_TRANSFERS=0
        while [ $COUNT_OF_TRANSFERS -lt $TRANSFERS ];
        do
            for NODE_ID in $(seq 1 $(get_count_of_genesis_nodes $NET_ID))
            do
                COUNT_OF_TRANSFERS=$((COUNT_OF_TRANSFERS + 1))
                log "... ... #$COUNT_OF_TRANSFERS :: $(_dispatch_deploy)"
                if [[ $COUNT_OF_TRANSFERS -eq $TRANSFERS ]]; then
                    break
                fi
                sleep $TRANSFER_INTERVAL
            done
        done

    # Specific node dispatch.
    else
        local NODE_ADDRESS=$(get_node_address_rpc $NET_ID $NODE_ID)
        for TRANSFER_ID in $(seq 1 $TRANSFERS)
        do
            log "... ... #$TRANSFER_ID :: $(_dispatch_deploy)"
            sleep $TRANSFER_INTERVAL
        done
    fi

    log "dispatched $TRANSFERS native transfers"
}

#######################################
# Dispatches previously prepared native transfers to a test net.
# Arguments:
#   Network ordinal identifier.
#   Node ordinal identifier.
#   Transfer dispatch interval.
#######################################
function do_transfer_wasm_dispatch()
{
    local NET_ID=${1}
    local NODE_ID=${2}
    local TRANSFER_INTERVAL=${3}

    local CP1_SECRET_KEY=$(get_path_to_secret_key $NET_ID $NCTL_ACCOUNT_TYPE_FAUCET)
    local NODE_ADDRESS=$(get_node_address_rpc $NET_ID $NODE_ID)
    local PATH_TO_CLIENT=$(get_path_to_client $NET_ID)
    local PATH_TO_NET=$(get_path_to_net $NET_ID)    

    for USER_ID in $(seq 1 $(get_count_of_users $NET_ID))
    do
        for BATCH_ID in $(seq 1 10000)
        do
            local PATH_TO_BATCH=$PATH_TO_NET/deploys/transfer-native/batch-$BATCH_ID/user-$USER_ID
            if [ ! -d $PATH_TO_BATCH ]; then
                break
            else
                for TRANSFER_ID in $(seq 1 100000)
                do
                    local PATH_TO_DEPLOY=$PATH_TO_BATCH/transfer-$TRANSFER_ID.json
                    if [ ! -f $PATH_TO_DEPLOY ]; then
                        break
                    else
                        DEPLOY_HASH=$(
                            $PATH_TO_CLIENT send-deploy \
                                --node-address $NODE_ADDRESS \
                                --input $PATH_TO_DEPLOY \
                                | jq '.result.deploy_hash' \
                                | sed -e 's/^"//' -e 's/"$//'                                
                        )
                        log "user #$USER_ID :: batch #$BATCH_ID :: deploy #$TRANSFER_ID :: $DEPLOY_HASH"
                    fi
                done
            fi
        done
    done
}

#######################################
# Dispatches previously prepared native transfers to a test net.
# Arguments:
#   Network ordinal identifier.
#   Node ordinal identifier.
#   Transfer dispatch interval.
#######################################
function do_transfer_native_prepare()
{
    local NET_ID=${1}
    local NODE_ID=${2}
    local TRANSFER_INTERVAL=${3}

    local CP1_SECRET_KEY=$(get_path_to_secret_key $NET_ID $NCTL_ACCOUNT_TYPE_FAUCET)
    local NODE_ADDRESS=$(get_node_address_rpc $NET_ID $NODE_ID)
    local PATH_TO_CLIENT=$(get_path_to_client $NET_ID)
    local PATH_TO_NET=$(get_path_to_net $NET_ID)    

    for USER_ID in $(seq 1 $(get_count_of_users $NET_ID))
    do
        for BATCH_ID in $(seq 1 10000)
        do
            local PATH_TO_BATCH=$PATH_TO_NET/deploys/transfer-native/batch-$BATCH_ID/user-$USER_ID
            if [ ! -d $PATH_TO_BATCH ]; then
                break
            else
                for TRANSFER_ID in $(seq 1 100000)
                do
                    local PATH_TO_DEPLOY=$PATH_TO_BATCH/transfer-$TRANSFER_ID.json
                    if [ ! -f $PATH_TO_DEPLOY ]; then
                        break
                    else
                        DEPLOY_HASH=$(
                            $PATH_TO_CLIENT send-deploy \
                                --node-address $NODE_ADDRESS \
                                --input $PATH_TO_DEPLOY \
                                | jq '.result.deploy_hash' \
                                | sed -e 's/^"//' -e 's/"$//'                                
                        )
                        log "user #$USER_ID :: batch #$BATCH_ID :: deploy #$TRANSFER_ID :: $DEPLOY_HASH"
                    fi
                done
            fi
        done
    done
}

#######################################
# Dispatches wasm transfers to a test net.
# Arguments:
#   Network ordinal identifier.
#   Node ordinal identifier.
#   Transfer amount.
#   User ordinal identifier.
#   Count of transfers to be dispatched.
#   Transfer dispatch interval.
#   Gas price.
#   Gas payment.
#######################################
function do_transfer_wasm()
{
    local NET_ID=${1}
    local NODE_ID=${2}
    local AMOUNT=${3}
    local USER_ID=${4}
    local TRANSFERS=${5}
    local TRANSFER_INTERVAL=${6}
    local GAS=${7}
    local PAYMENT=${8}

    local CHAIN_NAME=$(get_chain_name $NET_ID)
    local CP1_SECRET_KEY=$(get_path_to_secret_key $NET_ID $NCTL_ACCOUNT_TYPE_FAUCET)
    local CP1_PUBLIC_KEY=$(get_account_key $NET_ID $NCTL_ACCOUNT_TYPE_FAUCET)
    local CP2_PUBLIC_KEY=$(get_account_key $NET_ID $NCTL_ACCOUNT_TYPE_USER $USER_ID)
    local CP2_ACCOUNT_HASH=$(get_account_hash $CP2_PUBLIC_KEY)
    local PATH_TO_CLIENT=$(get_path_to_client $NET_ID)
    local PATH_TO_CONTRACT=$(get_path_to_contract $NET_ID "transfer_to_account_u512.wasm")

    log "dispatching $TRANSFERS wasm transfers"
    log "... network=$NET_ID"
    log "... node=$NODE_ID"
    log "... transfer amount=$AMOUNT"
    log "... transfer contract=$PATH_TO_CONTRACT"
    log "... transfer interval=$TRANSFER_INTERVAL (s)"
    log "... counter-party 1 public key=$CP1_PUBLIC_KEY"
    log "... counter-party 2 public key=$CP2_PUBLIC_KEY"
    log "... counter-party 2 account hash=$CP2_ACCOUNT_HASH"
    log "... dispatched deploys:"

    function _dispatch_deploy {
        local NODE_ADDRESS=$(get_node_address_rpc $NET_ID $NODE_ID)
        echo $(
            $PATH_TO_CLIENT put-deploy \
                --chain-name $CHAIN_NAME \
                --gas-price $GAS \
                --node-address $NODE_ADDRESS \
                --payment-amount $PAYMENT \
                --secret-key $CP1_SECRET_KEY \
                --session-arg "amount:u512='$AMOUNT'" \
                --session-arg "target:account_hash='account-hash-$CP2_ACCOUNT_HASH'" \
                --session-path $PATH_TO_CONTRACT \
                --ttl "1day" \
                | jq '.result.deploy_hash' \
                | sed -e 's/^"//' -e 's/"$//'
            )
    }

    # Round robin dispatch.
    if [ $NODE_ID = "all" ]; then
        local COUNT_OF_TRANSFERS=0
        while [ $COUNT_OF_TRANSFERS -lt $TRANSFERS ];
        do
            for NODE_ID in $(seq 1 $(get_count_of_genesis_nodes $NET_ID))
            do
                COUNT_OF_TRANSFERS=$((COUNT_OF_TRANSFERS + 1))
                log "... ... #$COUNT_OF_TRANSFERS :: $(_dispatch_deploy)"
                if [[ $COUNT_OF_TRANSFERS -eq $TRANSFERS ]]; then
                    break
                fi
                sleep $TRANSFER_INTERVAL
            done
        done

    # Specific node dispatch.
    else
        local NODE_ADDRESS=$(get_node_address_rpc $NET_ID $NODE_ID)
        for TRANSFER_ID in $(seq 1 $TRANSFERS)
        do
            DEPLOY_HASH=$(_dispatch_deploy)
            log "... ... #$TRANSFER_ID :: $DEPLOY_HASH"
            sleep $TRANSFER_INTERVAL
        done
    fi

    log "dispatched $TRANSFERS wasm transfers"
}

#######################################
# Dispatches previously prepared wasm transfers to a test net.
# Arguments:
#   Network ordinal identifier.
#   Node ordinal identifier.
#   Transfer dispatch interval.
#######################################
function do_transfer_wasm_dispatch()
{
    local NET_ID=${1}
    local NODE_ID=${2}
    local TRANSFER_INTERVAL=${3}

    local CP1_SECRET_KEY=$(get_path_to_secret_key $NET_ID $NCTL_ACCOUNT_TYPE_FAUCET)
    local NODE_ADDRESS=$(get_node_address_rpc $NET_ID $NODE_ID)
    local PATH_TO_CLIENT=$(get_path_to_client $NET_ID)
    local PATH_TO_NET=$(get_path_to_net $NET_ID)    

    for USER_ID in $(seq 1 $(get_count_of_users $NET_ID))
    do
        for BATCH_ID in $(seq 1 10000)
        do
            local PATH_TO_BATCH=$PATH_TO_NET/deploys/transfer-wasm/batch-$BATCH_ID/user-$USER_ID
            if [ ! -d $PATH_TO_BATCH ]; then
                break
            else
                for TRANSFER_ID in $(seq 1 100000)
                do
                    local PATH_TO_DEPLOY=$PATH_TO_BATCH/transfer-$TRANSFER_ID.json
                    if [ ! -f $PATH_TO_DEPLOY ]; then
                        break
                    else
                        DEPLOY_HASH=$(
                            $PATH_TO_CLIENT send-deploy \
                                --node-address $NODE_ADDRESS \
                                --input $PATH_TO_DEPLOY \
                                | jq '.result.deploy_hash' \
                                | sed -e 's/^"//' -e 's/"$//'                                
                        )
                        log "user #$USER_ID :: batch #$BATCH_ID :: deploy #$TRANSFER_ID :: $DEPLOY_HASH"
                    fi
                done
            fi
        done
    done
}

#######################################
# Prepares wasm transfers for dispatch to a test net.
# Arguments:
#   Network ordinal identifier.
#   Node ordinal identifier.
#   Transfer amount.
#   User ordinal identifier.
#   Count of transfer batches to be dispatched.
#   Size of transfer batches to be dispatched.
#   Gas price.
#   Gas payment.
#######################################
function do_transfer_wasm_prepare()
{
    local NET_ID=${1}
    local NODE_ID=${2}
    local AMOUNT=${3}
    local BATCH_COUNT=${4}
    local BATCH_SIZE=${5}
    local GAS=${6}
    local PAYMENT=${7}

    local CHAIN_NAME=$(get_chain_name $NET_ID)
    local CP1_SECRET_KEY=$(get_path_to_secret_key $NET_ID $NCTL_ACCOUNT_TYPE_FAUCET)
    local CP1_PUBLIC_KEY=$(get_account_key $NET_ID $NCTL_ACCOUNT_TYPE_FAUCET)
    local PATH_TO_CLIENT=$(get_path_to_client $NET_ID)    
    local PATH_TO_CONTRACT=$(get_path_to_contract $NET_ID "transfer_to_account_u512.wasm")
    local PATH_TO_NET=$(get_path_to_net $NET_ID)    

    if [ -d $PATH_TO_NET/deploys/transfer-wasm ]; then
        rm -rf $PATH_TO_NET/deploys/transfer-wasm
    fi

    for USER_ID in $(seq 1 $(get_count_of_users $NET_ID))
    do
        local CP2_PUBLIC_KEY=$(get_account_key $NET_ID $NCTL_ACCOUNT_TYPE_USER $USER_ID)
        local CP2_ACCOUNT_HASH=$(get_account_hash $CP2_PUBLIC_KEY)

        for BATCH_ID in $(seq 1 $BATCH_COUNT)
        do
            local PATH_TO_OUTPUT=$PATH_TO_NET/deploys/transfer-wasm/batch-$BATCH_ID/user-$USER_ID
            mkdir -p $PATH_TO_OUTPUT

            for TRANSFER_ID in $(seq 1 $BATCH_SIZE)
            do
                local PATH_TO_OUTPUT_UNSIGNED=$PATH_TO_OUTPUT/transfer-$TRANSFER_ID-unsigned.json
                $PATH_TO_CLIENT make-deploy \
                    --output $PATH_TO_OUTPUT_UNSIGNED \
                    --chain-name $CHAIN_NAME \
                    --gas-price $GAS \
                    --payment-amount $PAYMENT \
                    --secret-key $CP1_SECRET_KEY \
                    --session-arg "amount:u512='$AMOUNT'" \
                    --session-arg "target:account_hash='account-hash-$CP2_ACCOUNT_HASH'" \
                    --session-path $PATH_TO_CONTRACT \
                    --ttl "1day"

                local PATH_TO_OUTPUT_SIGNED=$PATH_TO_OUTPUT/transfer-$TRANSFER_ID.json
                $PATH_TO_CLIENT sign-deploy \
                    --secret-key $CP1_SECRET_KEY \
                    --input $PATH_TO_OUTPUT_UNSIGNED \
                    --output $PATH_TO_OUTPUT_SIGNED
            done
        done
    done

    rm $PATH_TO_NET/deploys/transfer-wasm/batch-*/user-*/*-unsigned.json    
}