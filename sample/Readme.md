# rust-dlc sample

Example of combining the various components of the rust-dlc library together with the custom message handler of [rust-lightning](https://github.com/rust-bitcoin/rust-lightning) to enable networked communication.

Originally based on the code from the [ldk sample](https://github.com/lightningdevkit/ldk-sample).

Example configurations and contract input are available in the [examples](./examples) folder.
In order to use the [example contract](./examples/contracts/numerical_contract_input.json) you will need to update the `event_id`.
Replace the part after `btcusd` with a UNIX timestamp in the future.


## Quick run

To give a quick try to this sample, run the following set of commands (assuming that the working directory is the one in which this readme is located and that docker and docker-compose is available on your machine):

```bash
docker-compose --profile oracle up -d
docker compose exec bitcoind /scripts/create_wallets.sh
cargo run ./examples/configurations/alice.yml
```

In a different terminal:
```bash
cargo run ./examples/configurations/bob.yml
```

Update the [example contract](./examples/contracts/numerical_contract_input.json#L82) replacing the number after `btcusd` with a unix timestamp some time in the future (this will correspond to the contract maturity date).

### On chain DLC

From the second instance (Bob), type:
```
offercontract 02c84f8e151590e718d22e528c55f14c0042c66e68c3f793d7b3b8bf5ae630c648@127.0.0.1:9000 ./examples/contracts/numerical_contract_input.json
```
Replacing the public key by the one that was displayed when starting the first instance.

From the first instance (Alice), type:
```
listoffers
```
You should see the id of the contract that was offered by Bob.
A JSON file with contract information should also have been saved in Alice's data folder (`./dlc_sample_alice/offers/xxx.json`).

Alice can now accept the offer by typing:
```
acceptoffer xxxxx
```
replacing `xxxxx` with the contract id that was previously displayed.

This will make Alice's instance send an accept message to Bob.
In Bob's instance, typing `listcontracts` will trigger the processing of the message, and you should see that the contract will be in `Signed`, as Bob will automatically reply to Alice with a `Sign message`.

Typing the same command in Alice's instance will make Alice broadcast the fund transaction.

Now in yet another terminal (still from the same location) run:
```bash
docker compose exec bitcoind /scripts/generate_blocks.sh
```

This will generate some blocks so that the fund transaction is confirmed.

Typing `listcontracts` in either instance should now show the contract as `Confirmed`.

Once the maturity of the contract is reached, typing `listcontracts` once more will retrieve the attestation from the oracle and close the contract, displaying the event outcome (in decomposed binary format) and the profit and loss for the given instance.

### DLC channels

From the second instance (Bob), type:
```
offerchannel 02c84f8e151590e718d22e528c55f14c0042c66e68c3f793d7b3b8bf5ae630c648@127.0.0.1:9000 ./examples/contracts/numerical_contract_input.json
```
Replacing the public key by the one that was displayed when starting the first instance.

From the first instance (Alice), type:
```
listchanneloffers
```
You should see the id of the contract that was offered by Bob.
A JSON file with contract information should also have been saved in Alice's data folder (`./dlc_sample_alice/offers/xxx.json`).

Alice can now accept the offer by typing:
```
acceptchannel xxxxx
```
replacing `xxxxx` with the channel id that was previously displayed.

This will make Alice's instance send an accept message to Bob.
In Bob's instance, typing `listsignedchannels` will trigger the processing of the message, and you should see that the channel id being displayed (different than the one during the offer as it was a temporary id previously).

Typing the same command in Alice's instance will make Alice broadcast the fund transaction.

Now in yet another terminal (still from the same location) run:
```bash
docker compose exec bitcoind /scripts/generate_blocks.sh
```

This will generate some blocks so that the fund transaction is confirmed.
The channel is now setup.

#### Settle the contract in the channel

One of the party can offer a settlement of the contract within the channel.
To do so, use the `offersettlechannel` command, passing in the channel id (that you can get using the `listsignedchannels` command), as well as the proposed payout for the counter party.

In the other terminal, use the `listsettlechanneloffers` to display the received settle offer.

To accept the offer, use the `acceptsettlechanneloffer` passing the channel id as a parameter.
Three messages need to be exchanged between the peers to properly settle the channel, press `Enter` once in the terminal where the settle offer was made, once where the settle offer was received and once more where the settle offer was made for the settlement to be finalized. 

To reject the offer, use the `rejectsettlechanneloffer` command, passing the channel id as a parameter.

#### Renew the contract in the channel

One of the party can offer to renew the contract in the channel.
To do so, use the `offerchannelrenew` command, passing in the channel id (that you can get using the `listsignedchannels` command), the proposed payout for the counter party, and the path to the json file containing the information about the contract to offer.

In the other terminal, use the `listrenewchanneloffers` to display the received settle offer.

To accept the offer, use the `acceptrenewchanneloffer` passing the channel id as a parameter.
Three messages need to be exchanged between the peers to properly settle the channel, press `Enter` once in the terminal where the settle offer was made, once where the settle offer was received and once more where the settle offer was made for the settlement to be finalized. 

To reject the offer, use the `rejectrenewchanneloffer` command, passing the channel id as a parameter.
