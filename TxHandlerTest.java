import java.security.*;
import junit.framework.TestCase;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class TxHandlerTest extends TestCase {
	private KeyPair sender;
	private KeyPair receiver;
	private KeyPair attacker;
	private UTXOPool utxoPool;
	private Transaction genesisTx;
	private TxHandler txHandler;
	private KeyPair user3;
	private KeyPair user4;

	//Generate Keys
	private void GenPairKey() throws NoSuchAlgorithmException, NoSuchProviderException {
		KeyPairGenerator GPK = KeyPairGenerator.getInstance("DSA", "SUN");
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
		GPK.initialize(1024, random);
		sender = GPK.generateKeyPair();
		receiver = GPK.generateKeyPair();
		attacker = GPK.generateKeyPair();
		user3 = GPK.generateKeyPair();
		user4 = GPK.generateKeyPair();
	}

	//Generate GenesisTx, UTXOPool and txHandler
	private void GenesisState() {
		genesisTx = new Transaction();

		genesisTx.addOutput(100, sender.getPublic());
		genesisTx.finalize();
		UTXOPool utxopool = new UTXOPool();
		UTXO utxo = new UTXO(genesisTx.getHash(), 0);
		utxopool.addUTXO(utxo, genesisTx.getOutput(0));

		txHandler = new TxHandler(utxopool);
	}

	//Generate TxSign class, TxSign is to sign the message via privkey
	private byte[] TxSign(PrivateKey PrivKey, byte[] message)
			throws NoSuchAlgorithmException, NoSuchProviderException, SignatureException, InvalidKeyException {
		Signature sig = Signature.getInstance("DSA", "SUN");
		sig.initSign(PrivKey);
		sig.update(message);
		return sig.sign();

	}

	public void setUp() throws Exception {
		GenPairKey();
		GenesisState();

	}
	@Test
	public void testAllOutputsInUTXOPool() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {

		// Create two transactions that use the same output
		Transaction tx1 = new Transaction();
		tx1.addInput(genesisTx.getHash(), 0);
		tx1.addOutput(50, sender.getPublic());
		tx1.addOutput(50, receiver.getPublic());
		byte[] txRawData1 = tx1.getRawDataToSign(0);
		byte[] signature1 = TxSign(sender.getPrivate(), txRawData1);
		tx1.addSignature(signature1, 0);
		tx1.finalize();

		Transaction tx2 = new Transaction();
		tx2.addOutput(30, receiver.getPublic());
		tx2.addInput(tx1.getHash(), 1);
		byte[] txRawData2 = tx2.getRawDataToSign(0);
		byte[] signature2 = TxSign(sender.getPrivate(), txRawData1);
		tx2.addSignature(signature2, 0);
		tx2.finalize();
		// Add tx1 to UTXO pool
		genesisTx = new Transaction();
		genesisTx.addOutput(100, sender.getPublic());
		genesisTx.finalize();
		UTXOPool utxopool = new UTXOPool();
		UTXO utxo = new UTXO(genesisTx.getHash(), 0);
		utxopool.addUTXO(utxo, genesisTx.getOutput(0));
		UTXO utxo1 = new UTXO(tx1.getHash(), 1);
		utxopool.removeUTXO(utxo);
		utxopool.addUTXO(utxo1, tx1.getOutput(1));

		// Check that tx1 is valid
		assertTrue(txHandler.isValidTx(tx1));

		// Check that tx2 is not valid due to the claimed output not being in the UTXO pool
		assertFalse(txHandler.isValidTx(tx2));
	}

	@Test
	public void testValidTx1() throws NoSuchAlgorithmException, SignatureException, NoSuchProviderException, InvalidKeyException {
		// create a new transaction spending from the genesis UTXO
		Transaction tx = new Transaction();
		tx.addInput(genesisTx.getHash(), 0);
		tx.addOutput(100, receiver.getPublic());

		// sign the transaction with the sender's private key
		byte[] txRawData = tx.getRawDataToSign(0);
		byte[] signature = TxSign(sender.getPrivate(), txRawData);
		tx.addSignature(signature, 0);

		// test if the transaction is valid
		assertTrue(txHandler.isValidTx(tx));
	}
	//
	@Test
	public void testValidTx2() throws NoSuchAlgorithmException, SignatureException, NoSuchProviderException, InvalidKeyException {
		// create a new transaction spending from the genesis UTXO
		Transaction tx2 = new Transaction();
		tx2.addInput(genesisTx.getHash(),0);
		tx2.addOutput(50,receiver.getPublic());
		tx2.addOutput(50,receiver.getPublic());

		// sign the transaction with the sender's private key
		byte[] txRawData2 = tx2.getRawDataToSign(0);
		byte[] signature2 = TxSign(sender.getPrivate(), txRawData2);
		tx2.addSignature(signature2,0);

		// test if the transaction is valid
		assertTrue(txHandler.isValidTx(tx2));
	}
	@Test
	public void testValidSumValue() throws NoSuchAlgorithmException, SignatureException, NoSuchProviderException, InvalidKeyException {
		// create a new transaction spending from the genesis UTXO
		Transaction tx2 = new Transaction();
		tx2.addInput(genesisTx.getHash(),0);
		tx2.addOutput(60,receiver.getPublic());
		tx2.addOutput(60,receiver.getPublic());

		// sign the transaction with the sender's private key
		byte[] txRawData2 = tx2.getRawDataToSign(0);
		byte[] signature2 = TxSign(sender.getPrivate(), txRawData2);
		tx2.addSignature(signature2,0);

		// test if the transaction is valid
		assertFalse(txHandler.isValidTx(tx2));
	}
	@Test
	public void testInValidTx() throws NoSuchAlgorithmException, SignatureException, NoSuchProviderException, InvalidKeyException {
		// create a new transaction spending from the genesis UTXO
		Transaction tx = new Transaction();
		tx.addInput(genesisTx.getHash(), 0);
		tx.addOutput(100, receiver.getPublic());

		// sign the transaction with the sender's private key
		byte[] txRawData = tx.getRawDataToSign(0);
		byte[] signature = TxSign(receiver.getPrivate(), txRawData);
		tx.addSignature(signature, 0);

		// test if the transaction is valid
		assertFalse(txHandler.isValidTx(tx));
	}

		@Test
		public void testInvalidTxDoubleSpend () throws NoSuchAlgorithmException, SignatureException, NoSuchProviderException, InvalidKeyException {
			genesisTx = new Transaction();
			genesisTx.addOutput(100, sender.getPublic());
			genesisTx.finalize();
			UTXOPool utxopool = new UTXOPool();
			UTXO utxo = new UTXO(genesisTx.getHash(), 0);
			utxopool.addUTXO(utxo, genesisTx.getOutput(0));
		// create two new transactions spending from the genesis UTXO
			Transaction tx1 = new Transaction();
			tx1.addInput(genesisTx.getHash(), 0);
			tx1.addOutput(100, receiver.getPublic());
			byte[] txRawData1 = tx1.getRawDataToSign(0);
			byte[] signature1 = TxSign(sender.getPrivate(), txRawData1);
			tx1.addSignature(signature1, 0);
			tx1.finalize();
			Transaction tx2 = new Transaction();
			tx2.addInput(genesisTx.getHash(), 1);
			tx2.addOutput(100, attacker.getPublic());
			byte[] txRawData2 = tx2.getRawDataToSign(0);
			byte[] signature2 = TxSign(sender.getPrivate(), txRawData2);
			tx2.addSignature(signature2, 0);
			tx2.finalize();
			// test if the first transaction is valid

			assertTrue(txHandler.isValidTx(tx1));
			utxopool.removeUTXO(utxo);
			UTXO utxo1 = new UTXO(tx1.getHash(), 0);
			utxopool.addUTXO(utxo, tx1.getOutput(0));
			// test if the second transaction is invalid (double spend)
			assertFalse(txHandler.isValidTx(tx2));
		}

		@Test
		public void testInvalidTxNegativeOutputValue () throws NoSuchAlgorithmException, SignatureException, NoSuchProviderException, InvalidKeyException {
			// create a new transaction spending from the genesis UTXO with a negative output value
			Transaction tx3 = new Transaction();
			tx3.addInput(genesisTx.getHash(), 0);
			tx3.addOutput(-100, receiver.getPublic());
			byte[] txRawData = tx3.getRawDataToSign(0);
			byte[] signature = TxSign(sender.getPrivate(), txRawData);
			tx3.addSignature(signature,0);
			// test if the second transaction is invalid (double spend)
			assertFalse(txHandler.isValidTx(tx3));
		}
		@Test
		public void testInvalidMultiClaims () throws NoSuchAlgorithmException, SignatureException, NoSuchProviderException, InvalidKeyException {
			// create a new transaction spending from the genesis UTXO with a negative output value
			Transaction tx4 = new Transaction();
			tx4.addInput(genesisTx.getHash(), 0);
			tx4.addInput(genesisTx.getHash(), 0);
			tx4.addOutput(100, receiver.getPublic());
			byte[] txRawData = tx4.getRawDataToSign(0);
			byte[] signature1 = TxSign(sender.getPrivate(), txRawData);
			byte[] signature2 = TxSign(sender.getPrivate(), txRawData);
			tx4.addSignature(signature1,0);
			tx4.addSignature(signature2,0);
			// test if the second transaction is invalid (double spend)
			assertFalse(txHandler.isValidTx(tx4));
		}
		@Test
		public void testHandleTxs() throws Exception {
			genesisTx = new Transaction();
			genesisTx.addOutput(100, sender.getPublic());
			genesisTx.finalize();
			UTXOPool utxopool = new UTXOPool();
			UTXO utxo = new UTXO(genesisTx.getHash(), 0);
			utxopool.addUTXO(utxo, genesisTx.getOutput(0));
			//generaet Txs
			Transaction tx1 = new Transaction();
			tx1.addInput(genesisTx.getHash(), utxo.getIndex());
			tx1.addOutput(40, receiver.getPublic());
			tx1.addOutput(60, user3.getPublic());
			byte[] txRawData1 = tx1.getRawDataToSign(0);
			byte[] signature1 = TxSign(sender.getPrivate(), txRawData1);
			tx1.addSignature(signature1,0);
			tx1.finalize();
			assertTrue(txHandler.isValidTx(tx1));
			Transaction[] acceptedTxs1 = txHandler.handleTxs(new Transaction[] { tx1 });
			assertEquals(acceptedTxs1.length, 1);

			Transaction tx2 = new Transaction();
			tx2.addInput(tx1.getHash(), 0);
			tx2.addOutput(30, user4.getPublic());
			byte[] txRawData2 = tx2.getRawDataToSign(0);
			byte[] signature2 = TxSign(receiver.getPrivate(),txRawData2 );
			tx2.addSignature(signature2,0);
			tx2.finalize();
			assertTrue(txHandler.isValidTx(tx2));
			Transaction[] acceptedTxs2 = txHandler.handleTxs(new Transaction[] { tx2 });
			assertEquals(acceptedTxs2.length, 1);

			Transaction tx3 = new Transaction();
			tx3.addInput(tx1.getHash(), 1);
			tx3.addOutput(50, user4.getPublic());
			byte[] txRawData3 = tx3.getRawDataToSign(0);
			byte[] signature3 = TxSign(user3.getPrivate(), txRawData3);
			tx3.addSignature(signature3,0);
			tx3.finalize();
			assertTrue(txHandler.isValidTx(tx3));
			Transaction[] acceptedTxs3 = txHandler.handleTxs(new Transaction[] { tx3 });
			assertEquals(acceptedTxs3.length, 1);

			Transaction tx4 = new Transaction();
			tx4.addInput(tx2.getHash(), 0);
			tx4.addInput(tx3.getHash(), 0);
			tx4.addOutput(80, sender.getPublic());

			byte[] signature4_1 = TxSign(user4.getPrivate(),tx4.getRawDataToSign(0));
			byte[] signature4_2 = TxSign(user4.getPrivate(),tx4.getRawDataToSign(1));
			tx4.addSignature(signature4_1,0);
			tx4.addSignature(signature4_2,1);
			tx4.finalize();
			assertTrue(txHandler.isValidTx(tx4));
			Transaction[] acceptedTxs4 = txHandler.handleTxs(new Transaction[] { tx4 });
			assertEquals(acceptedTxs4.length, 1);


			// Create a set of transactions
			Transaction[] txs = new Transaction[]{tx1, tx2, tx3, tx4};

			// Create a TxHandler instance
			TxHandler txHandler = new TxHandler(utxopool);

			// Handle the transactions
			Transaction[] acceptedTxs = txHandler.handleTxs(txs);
			UTXO utxo1 = new UTXO(tx1.getHash(), 0);
			UTXO utxo2 = new UTXO(tx2.getHash(), 0);
			assertFalse(txHandler.utxoPool.contains(utxo1));
			assertFalse(txHandler.utxoPool.contains(utxo2));
			UTXO utxo4 = new UTXO(tx4.getHash(), 0);
			assertTrue(txHandler.utxoPool.contains(utxo4));
		}
}