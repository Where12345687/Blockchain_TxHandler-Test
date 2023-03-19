import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;
//import org.junit.Test;

public class TxHandler {

    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    public UTXOPool utxoPool;
    public TxHandler(UTXOPool utxoPool) {
        this.utxoPool = new UTXOPool(utxoPool);
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool,
     * (2) the signatures on each input of {@code tx} are valid,
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     *     values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
        Set<UTXO> utxoSet = new HashSet<>();
        for (int i = 0; i < tx.getInputs().size(); i++) {
            Transaction.Input input = tx.getInput(i);
            // Check if any output claimed by tx is in the current UTXO pool
            UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);
            if (!utxoPool.contains(utxo)) {
                return false;
            }
            // Check no UTXO is claimed multiple times by tx
            if (!utxoSet.add(utxo)) {
                return false;
            }
            //Check
            Transaction.Output output = utxoPool.getTxOutput(utxo);
            if (!Crypto.verifySignature(output.address, tx.getRawDataToSign(i), input.signature)) {
                return false;
            }
        }

        // Check if any of tx's output values are no-negative
        for (Transaction.Output output : tx.getOutputs()) {
            if (output.value < 0) {
                return false;
            }
        }

        // Check if the sum of tx's input values is more than the sum of its output values
        double inputSum = 0;
        double outputSum = 0;
        for (Transaction.Input input : tx.getInputs()) {
            UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);
            Transaction.Output output = utxoPool.getTxOutput(utxo);
            inputSum += output.value;
        }
        for (Transaction.Output output : tx.getOutputs()) {
            outputSum += output.value;
        }
        if (inputSum < outputSum) {
            return false;
        }
        // If none of the above conditions are false, return true
        return true;
    }


    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {

        ArrayList<Transaction> acceptedTxs = new ArrayList<>();
        for (Transaction tx : possibleTxs) {
            if (isValidTx(tx)) {
                acceptedTxs.add(tx);
                // remove spent UTXOs from UTXOPool
                for (Transaction.Input input : tx.getInputs()) {
                    UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);
                    utxoPool.removeUTXO(utxo);
                }
                // add new UTXOs to UTXOPool
                for (int i = 0; i < tx.getOutputs().size(); i++) {
                    UTXO utxo = new UTXO(tx.getHash(), i);
                    utxoPool.addUTXO(utxo, tx.getOutput(i));
                }
            }
        }

        Transaction[] acceptedTxArray = new Transaction[acceptedTxs.size()];
        return acceptedTxs.toArray(acceptedTxArray);
    }

}