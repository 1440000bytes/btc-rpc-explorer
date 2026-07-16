"use strict";

const CATALOG = require("./walletFingerprints.json");
const WALLETS = Object.keys(CATALOG.wallets);

const STRONG_LOWR_SIGS = 6;

const REFERENCES = {
	"Anti-fee-sniping": "https://bitcoinops.org/en/topics/fee-sniping/",
	"nVersion": "https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki",
	"RBF signaling": "https://github.com/bitcoin/bips/blob/master/bip-0125.mediawiki",
	"nSequence value": "https://github.com/bitcoin/bips/blob/master/bip-0125.mediawiki",
	"Input script types": "https://en.bitcoin.it/wiki/Privacy#Wallet_fingerprinting",
	"Public keys": "https://en.bitcoin.it/wiki/Privacy#Wallet_fingerprinting",
	"Low-R grinding": "https://bitcoinops.org/en/topics/low-r-grinding/",
	"Signature hash type": "https://en.bitcoin.it/wiki/OP_CHECKSIG",
	"OP_RETURN output": "https://en.bitcoin.it/wiki/OP_RETURN",
	"Outputs": "https://bitcoinops.org/en/topics/payment-batching/",
	"Output ordering": "https://github.com/bitcoin/bips/blob/master/bip-0069.mediawiki",
	"Input ordering": "https://github.com/bitcoin/bips/blob/master/bip-0069.mediawiki",
	"Address reuse": "https://en.bitcoin.it/wiki/Privacy#Address_reuse",
	"Detected change output": "https://en.bitcoin.it/wiki/Privacy#Change_address_detection",
	"Change type": "https://en.bitcoin.it/wiki/Privacy#Change_address_detection"
};

const TYPE_MAP = {
	"pubkeyhash": "p2pkh",
	"scripthash": "p2sh",
	"witness_v0_keyhash": "p2wpkh",
	"witness_v0_scripthash": "p2wsh",
	"witness_v1_taproot": "p2tr",
	"nulldata": "op_return",
	"pubkey": "p2pk",
	"multisig": "multisig"
};

function mapType(coreType) {
	if (!coreType) {
		return "unknown";
	}

	return TYPE_MAP[coreType] || coreType;
}

function toSats(value) {
	if (value == null) {
		return null;
	}

	return Math.round(Number(value) * 1e8);
}

function normalize(tx, txInputs) {
	const inputs = [];
	for (let i = 0; i < tx.vin.length; i++) {
		const vin = tx.vin[i];
		const prevout = txInputs ? txInputs[i] : null;

		inputs.push({
			prevoutKey: `${vin.txid}:${vin.vout}`,
			txid: vin.txid,
			vout: vin.vout,
			sequence: vin.sequence,
			witness: vin.txinwitness || [],
			scriptSigAsm: (vin.scriptSig && vin.scriptSig.asm) || "",
			type: prevout ? mapType(prevout.scriptPubKey && prevout.scriptPubKey.type) : "unknown",
			address: prevout ? ((prevout.scriptPubKey && prevout.scriptPubKey.address) || null) : null,
			valueSat: prevout ? toSats(prevout.value) : null
		});
	}

	const outputs = tx.vout.map((vout) => ({
		type: mapType(vout.scriptPubKey && vout.scriptPubKey.type),
		address: (vout.scriptPubKey && vout.scriptPubKey.address) || null,
		scriptHex: (vout.scriptPubKey && vout.scriptPubKey.hex) || "",
		valueSat: toSats(vout.value)
	}));

	return { inputs, outputs };
}

function uniqueTypes(items) {
	return Array.from(new Set(items.map((x) => x.type)));
}

function looksLikePubkey(hex) {
	if (!hex || /[^0-9a-fA-F]/.test(hex)) {
		return false;
	}

	if (hex.length === 66 && (hex.substring(0, 2) === "02" || hex.substring(0, 2) === "03")) {
		return true;
	}

	return hex.length === 130 && hex.substring(0, 2) === "04";
}

function sigAndPubkeyHex(input) {
	// Single-key witness spend, native (P2WPKH) or nested in P2SH (BIP49): [signature, pubkey]
	if (input.witness.length === 2 && looksLikePubkey(input.witness[1])) {
		return { sig: input.witness[0], pubkey: input.witness[1] };
	}

	if (input.scriptSigAsm) {
		const parts = input.scriptSigAsm.trim().split(/\s+/).filter(Boolean);

		// P2PKH: <signature> <pubkey>
		if (parts.length === 2 && looksLikePubkey(parts[1])) {
			return { sig: parts[0], pubkey: parts[1] };
		}

		// P2PK: <signature>
		if (parts.length === 1 && parts[0].substring(0, 2) === "30") {
			return { sig: parts[0], pubkey: null };
		}
	}

	return { sig: null, pubkey: null };
}

const SIGHASH_NAMES = {
	0x01: "SIGHASH_ALL",
	0x02: "SIGHASH_NONE",
	0x03: "SIGHASH_SINGLE",
	0x81: "SIGHASH_ALL|ANYONECANPAY",
	0x82: "SIGHASH_NONE|ANYONECANPAY",
	0x83: "SIGHASH_SINGLE|ANYONECANPAY"
};

function sighashName(byte) {
	return SIGHASH_NAMES[byte] || ("0x" + byte.toString(16));
}

function sighashOf(input) {
	// Taproot key-path spend: a single 64-byte (implicit SIGHASH_DEFAULT) or 65-byte witness element
	if (input.type === "p2tr" && input.witness.length === 1) {
		const w = input.witness[0];
		if (w.length === 128) {
			return "SIGHASH_DEFAULT";
		}
		if (w.length === 130) {
			return sighashName(parseInt(w.substring(128), 16));
		}

		return null;
	}

	// Single-key witness spend: the raw DER signature ends with the sighash byte
	if (input.witness.length === 2 && looksLikePubkey(input.witness[1])) {
		const wsig = input.witness[0];
		if (wsig.substring(0, 2) === "30" && wsig.length >= 4) {
			return sighashName(parseInt(wsig.substring(wsig.length - 2), 16));
		}

		return null;
	}

	// Legacy scriptSig: Bitcoin Core renders the sighash type as an annotation, e.g. "[ALL]"
	if (input.scriptSigAsm) {
		const m = input.scriptSigAsm.match(/\[([A-Z|]+)\]/);
		if (m) {
			return "SIGHASH_" + m[1];
		}
	}

	return null;
}

function compressedKeysOnly(inputs) {
	for (const input of inputs) {
		const { pubkey } = sigAndPubkeyHex(input);
		if (pubkey && pubkey.length >= 2 && pubkey.substring(0, 2) === "04") {
			return false;
		}
	}

	return true;
}

function ecdsaSignatureStats(inputs) {
	let examined = 0;
	let lowR = 0;
	let highR = 0;

	for (const input of inputs) {
		const { sig } = sigAndPubkeyHex(input);
		if (sig && sig.length >= 8 && sig.substring(0, 2) === "30") {
			const rLen = parseInt(sig.substring(6, 8), 16);
			if (isNaN(rLen)) {
				continue;
			}

			examined++;
			if (rLen > 32) {
				highR++;
			} else {
				lowR++;
			}
		}
	}

	return { examined, lowR, highR };
}

function bip69InputsSorted(inputs) {
	if (inputs.length <= 1) {
		return true;
	}

	const keys = inputs.map((i) => `${i.txid}:${String(i.vout).padStart(10, "0")}`);
	const sorted = keys.slice().sort();
	return JSON.stringify(keys) === JSON.stringify(sorted);
}

function bip69OutputsSorted(outputs) {
	if (outputs.length <= 1) {
		return true;
	}

	const pairs = outputs.map((o) => [o.valueSat, o.scriptHex]);
	const sorted = pairs.slice().sort((a, b) => {
		if (a[0] !== b[0]) {
			return a[0] - b[0];
		}

		return a[1].localeCompare(b[1]);
	});

	return JSON.stringify(pairs) === JSON.stringify(sorted);
}

function getChangeIndex(inputs, outputs) {
	if (outputs.length === 1) {
		return -1;
	}

	const inputTypes = inputs.map((i) => i.type);
	const outputTypes = outputs.map((o) => o.type);

	if (new Set(inputTypes).size === 1) {
		const matchCount = outputTypes.filter((t) => t === inputTypes[0]).length;
		if (matchCount === 1) {
			return outputTypes.indexOf(inputTypes[0]);
		}
	}

	const inputAddrs = new Set(inputs.map((i) => i.address).filter(Boolean));
	const sharedAddrIndexes = [];
	outputs.forEach((o, idx) => {
		if (o.address && inputAddrs.has(o.address)) {
			sharedAddrIndexes.push(idx);
		}
	});
	if (sharedAddrIndexes.length === 1) {
		return sharedAddrIndexes[0];
	}

	const inputValues = inputs.map((i) => i.valueSat).filter((v) => v != null);
	if (outputs.length === 2 && inputValues.length === inputs.length && inputValues.length > 0) {
		const minInput = Math.min(...inputValues);
		const belowMinInput = [];
		outputs.forEach((o, idx) => {
			if (o.valueSat != null && o.valueSat < minInput) {
				belowMinInput.push(idx);
			}
		});
		if (belowMinInput.length === 1) {
			return belowMinInput[0];
		}
	}

	const nonRoundIndexes = [];
	outputs.forEach((o, idx) => {
		if (o.valueSat != null && o.valueSat % 100 !== 0) {
			nonRoundIndexes.push(idx);
		}
	});
	if (nonRoundIndexes.length === 1) {
		return nonRoundIndexes[0];
	}

	return -2;
}

function addressReuse(inputs, outputs) {
	const inputAddrs = new Set(inputs.map((i) => i.address).filter(Boolean));
	return outputs.some((o) => o.address && inputAddrs.has(o.address));
}

function matchCatalog(f) {
	if (f.version !== 1 && f.version !== 2) {
		return [];
	}

	if (f.haveInputData && f.compressed === false) {
		return [];
	}

	return WALLETS.filter((name) => {
		const p = CATALOG.wallets[name];

		if (p.version !== f.version) {
			return false;
		}

		if (f.antiFeeSniping && p.anti_fee_sniping === "never") {
			return false;
		}
		if (!f.antiFeeSniping && p.anti_fee_sniping === "always") {
			return false;
		}

		if (f.rbf) {
			if (p.rbf === "never") {
				return false;
			}
			if (p.rbf === "native_segwit_only" && f.haveInputData && !f.onlyNativeSegwit) {
				return false;
			}
		} else {
			if (p.rbf === "always") {
				return false;
			}
			if (p.rbf === "native_segwit_only" && f.onlyNativeSegwit) {
				return false;
			}
		}

		if (p.nsequence && f.sequences && f.sequences.length > 0) {
			const allowed = p.nsequence.map((h) => parseInt(h, 16));
			if (!f.sequences.every((s) => allowed.includes(s))) {
				return false;
			}
		}

		if (f.haveInputData && f.multiType && p.multi_type_vin === "no") {
			return false;
		}

		if (f.haveInputData && f.lowR === "high" && p.low_r === "always") {
			return false;
		}
		if (f.haveInputData && f.lowR === "strong_low" && p.low_r === "no") {
			return false;
		}

		if (f.opReturn && p.op_return === "no") {
			return false;
		}

		if (f.batched && p.batching === "single") {
			return false;
		}

		if (f.outputsBip69 === false && p.bip69 === "always") {
			return false;
		}
		if (f.inputsBip69 === false && p.bip69 === "always") {
			return false;
		}

		if (f.haveInputData && f.reuse === true && p.address_reuse === "no") {
			return false;
		}
		if (f.haveInputData && f.reuse === false && p.address_reuse === "yes") {
			return false;
		}

		if (f.changePosition === "not_last" && p.change_position === "last") {
			return false;
		}

		if (f.changeType === "payment" && p.change_type !== "payment") {
			return false;
		}
		if (f.changeType === "input" && p.change_type === "payment") {
			return false;
		}

		return true;
	});
}

function analyzeTransaction(tx, txInputs, txBlockHeight, currentBlockHeight, extraSignatures) {
	if (!tx || !tx.vin || !tx.vout || (tx.vin[0] && tx.vin[0].coinbase)) {
		return { available: false };
	}

	const { inputs, outputs } = normalize(tx, txInputs);
	const haveInputData = inputs.every((i) => i.type !== "unknown");

	const signals = [];
	const add = (label, value, implication, privacy) => signals.push({ label, value, implication, privacy });

	const inTypes = uniqueTypes(inputs);
	const referenceHeight = (txBlockHeight && txBlockHeight > 0) ? txBlockHeight : currentBlockHeight;

	const facts = {
		version: tx.version,
		haveInputData,
		antiFeeSniping: tx.locktime > 0,
		rbf: inputs.some((i) => i.sequence != null && i.sequence < 0xfffffffe),
		sequences: Array.from(new Set(inputs.map((i) => i.sequence).filter((s) => s != null))),
		onlyNativeSegwit: haveInputData && inTypes.every((t) => t === "p2wpkh"),
		multiType: inTypes.length > 1,
		compressed: compressedKeysOnly(inputs),
		lowR: "none",
		opReturn: outputs.some((o) => o.type === "op_return"),
		batched: outputs.length > 2,
		outputsBip69: outputs.length > 1 ? bip69OutputsSorted(outputs) : null,
		inputsBip69: inputs.length > 1 ? bip69InputsSorted(inputs) : null,
		reuse: haveInputData ? addressReuse(inputs, outputs) : null,
		changePosition: "none",
		changeType: "none"
	};

	if (!facts.antiFeeSniping) {
		add("Anti-fee-sniping", "No (nLockTime = 0)",
			"Most wallets leave nLockTime at 0, which does not narrow much but rules out the wallets that always set it (Sparrow and Bull Bitcoin, plus Bitcoin Core and Electrum which set it most of the time).",
			null);
	} else {
		let detail = `nLockTime = ${tx.locktime}`;
		if (referenceHeight && referenceHeight > 0) {
			const delta = referenceHeight - tx.locktime;
			detail += (delta >= 0 && delta < 100) ? " (near chain tip)" : ` (${delta} blocks below tip)`;
		}

		add("Anti-fee-sniping", detail,
			"nLockTime set near the chain tip is the anti-fee-sniping pattern. Only wallets that do this are possible: Bitcoin Core, Electrum, Sparrow, Bull Bitcoin, Liana, Nunchuk and Wasabi.",
			"A non-zero locktime narrows the wallet to the anti-fee-sniping set.");
	}

	if (tx.version === 1) {
		add("nVersion", "1", "Transaction version 1 is used by Trust Wallet, Trezor and Ledger.", null);
	} else if (tx.version === 2) {
		add("nVersion", "2", "Version 2 rules out the wallets that still emit version-1 transactions (Ledger, Trezor, Trust).", null);
	} else {
		add("nVersion", String(tx.version), "Non-standard transaction version.", null);
	}

	if (facts.rbf) {
		add("RBF signaling", "Yes (nSequence < 0xFFFFFFFE)",
			"Opt-in Replace-By-Fee. Wallets that default to no RBF (Coinbase, Exodus, Wasabi) are ruled out.", null);
	} else {
		add("RBF signaling", "No (nSequence >= 0xFFFFFFFE)",
			"No RBF opt-in. The wallets that always signal RBF are ruled out: Bitcoin Core, Electrum, Ledger, Trezor, Trust, Sparrow, Bull Bitcoin, Liana and Nunchuk. Wallets that default to no RBF remain possible: Coinbase, Exodus, Wasabi, Cake (when spending unconfirmed coins), and Blue Wallet for its legacy, P2SH and taproot wallets.",
			null);
	}

	if (facts.sequences.length > 0) {
		const seqHexes = facts.sequences.map((s) => "0x" + s.toString(16).padStart(8, "0"));
		add("nSequence value", seqHexes.join(", "),
			"The exact nSequence value is wallet-specific: 0x80000000 is Blue Wallet's native segwit wallet; 0xFFFFFFFD is used by most RBF wallets (Bitcoin Core, Electrum, Sparrow, Liana, Bull Bitcoin, Cake); 0xFFFFFFFF by wallets that default to no RBF (Coinbase, Exodus, Wasabi).",
			null);
	}

	if (haveInputData) {
		if (inTypes.length > 1) {
			add("Input script types", inTypes.join(", "),
				"Spending more than one address type in one transaction is uncommon; most wallets use a single type.",
				"Mixing input types both fingerprints the wallet and links otherwise-separate address types to one owner.");
		} else {
			add("Input script types", inTypes[0] || "n/a", "All inputs share one script type.", null);
		}

		if (facts.compressed) {
			add("Public keys", "Compressed", "Compressed ECDSA public keys (standard for all modern wallets).", null);
		} else {
			add("Public keys", "Uncompressed key present",
				"Uncompressed public keys are legacy behavior and rare today.",
				"An uncompressed key is a strong, unusual fingerprint.");
		}

		const sigStats = ecdsaSignatureStats(inputs);
		const linked = extraSignatures || { low: 0, high: 0, linkedTxids: [] };
		const linkedCount = linked.linkedTxids ? linked.linkedTxids.length : 0;
		const totalHigh = sigStats.highR + (linked.high || 0);
		const totalLow = sigStats.lowR + (linked.low || 0);
		const totalExamined = totalLow + totalHigh;
		const across = linkedCount > 0 ? ` across this transaction and ${linkedCount} linked transaction(s)` : "";

		if (totalExamined > 0) {
			if (totalHigh > 0) {
				facts.lowR = "high";
				add("Low-R grinding", `No (${totalHigh} of ${totalExamined} ECDSA signature(s)${across} have a 33-byte R value)`,
					"A wallet that grinds for low-R signatures would never produce a high-R one, so a high-R signature rules out the grinding wallets (Bitcoin Core, Electrum, Sparrow, Bull Bitcoin, Liana).",
					null);
			} else if (totalExamined >= STRONG_LOWR_SIGS) {
				facts.lowR = "strong_low";
				add("Low-R grinding", `Yes (all ${totalExamined} ECDSA signature(s)${across} are low-R)`,
					`The chance of ${totalExamined} low-R signatures occurring by luck is about 1 in ${Math.pow(2, totalExamined)}, so this is strong evidence of deliberate low-R grinding (Bitcoin Core, Electrum, Sparrow, Bull Bitcoin, Liana).`,
					null);
			} else {
				facts.lowR = "low";
				add("Low-R grinding", `All ${totalExamined} ECDSA signature(s)${across} are low-R (32-byte R or smaller)`,
					`A non-grinding wallet still produces a low-R signature about half the time, so this is weak evidence (roughly 1 in ${Math.pow(2, totalExamined)}). Following the change chain to gather more of this wallet's signatures would strengthen or refute it.`,
					null);
			}
		}
	}

	const sighashes = Array.from(new Set(inputs.map(sighashOf).filter(Boolean)));
	const nonStandardSighash = sighashes.filter((s) => s !== "SIGHASH_ALL" && s !== "SIGHASH_DEFAULT");
	if (nonStandardSighash.length > 0) {
		add("Signature hash type", sighashes.join(", "),
			"Most wallets sign every input with SIGHASH_ALL (or SIGHASH_DEFAULT for taproot). A different flag is uncommon and usually indicates a collaborative transaction such as a coinjoin or a PSBT signed across wallets.",
			"A non-default sighash flag is a strong and unusual fingerprint.");
	}

	if (facts.opReturn) {
		add("OP_RETURN output", "Yes",
			"This transaction embeds data in an OP_RETURN output, which several wallets never create.", null);
	}

	if (facts.batched) {
		add("Outputs", `${outputs.length} (batched)`,
			"More than two outputs (batched payment) is something several single-recipient wallets never do.", null);
	}

	if (outputs.length > 1) {
		if (facts.outputsBip69) {
			add("Output ordering", "BIP-69 (lexicographic)",
				"Outputs are sorted per BIP-69. Deterministic ordering is itself a fingerprint; only some wallets do it.", null);
		} else {
			add("Output ordering", "Not BIP-69",
				"Outputs are not in BIP-69 order, ruling out wallets that always sort (Electrum, Trezor).", null);
		}
	}

	if (inputs.length > 1) {
		if (facts.inputsBip69) {
			add("Input ordering", "BIP-69 (lexicographic)", "Inputs are sorted per BIP-69.", null);
		} else {
			add("Input ordering", "Not BIP-69",
				"Inputs are not in BIP-69 order, ruling out wallets that always sort (Electrum, Trezor).", null);
		}
	}

	if (haveInputData) {
		if (facts.reuse) {
			add("Address reuse", "Yes (an output reuses an input address)",
				"Paying back to an address that was just spent. Most modern wallets avoid this.",
				"Address reuse directly links transactions and is one of the most damaging privacy leaks.");
		} else {
			add("Address reuse", "No", "No input address is reused as an output.", null);
		}

		const changeIndex = getChangeIndex(inputs, outputs);
		if (changeIndex >= 0) {
			const isLast = changeIndex === outputs.length - 1;
			facts.changePosition = isLast ? "last" : "not_last";
			add("Detected change output", `index ${changeIndex}${isLast ? " (last)" : " (not last)"}`,
				"Heuristic change detection (single matching script type / reused address / non-round amount).",
				"A predictable change position lets an observer separate the payment from the change.");

			const changeType = outputs[changeIndex].type;
			const otherOutputTypes = outputs.filter((_, i) => i !== changeIndex).map((o) => o.type);
			const matchesInput = inTypes.includes(changeType);
			const matchesOutput = otherOutputTypes.includes(changeType);
			if (matchesOutput && !matchesInput) {
				facts.changeType = "payment";
				add("Change type", "Matches the payment output type",
					"Bitcoin Core derives change matching the payment type; other wallets match the input type.", null);
			} else if (matchesInput && !matchesOutput) {
				facts.changeType = "input";
				add("Change type", "Matches the input type",
					"Change script type follows the inputs, which is what most non-Core wallets do.", null);
			}
		}
	}

	const candidates = matchCatalog(facts);

	signals.forEach((s) => { s.reference = REFERENCES[s.label] || null; });

	let verdict;
	let verdictClass;
	if (candidates.length === 0) {
		verdict = "Other / none of the profiled wallets";
		verdictClass = "secondary";
	} else if (candidates.length === 1) {
		verdict = candidates[0];
		verdictClass = "success";
	} else {
		verdict = `Unclear: ${candidates.join(", ")}`;
		verdictClass = "warning";
	}

	return {
		available: true,
		haveInputData,
		signals,
		walletCandidates: candidates,
		verdict,
		verdictClass,
		disclaimer: "Fingerprints are heuristic and probabilistic. A transaction may match a wallet it was not made with or unlisted wallet. It is also possible that the transaction was created and signed using different wallets."
	};
}

async function findSelfChangeParent(tx, txInputs, fetchTxWithInputs, seen) {
	const start = normalize(tx, txInputs);
	if (!start.inputs.every((i) => i.type !== "unknown")) {
		return null;
	}

	for (let i = 0; i < tx.vin.length; i++) {
		const vin = tx.vin[i];
		if (!vin || vin.coinbase || !vin.txid || seen.has(vin.txid)) {
			continue;
		}

		const parent = await fetchTxWithInputs(vin.txid);
		if (!parent || !parent.tx || !parent.tx.vout) {
			continue;
		}

		const parentNorm = normalize(parent.tx, parent.txInputs);
		if (!parentNorm.inputs.every((p) => p.type !== "unknown")) {
			continue;
		}

		const parentChange = getChangeIndex(parentNorm.inputs, parentNorm.outputs);
		if (parentChange >= 0 && parentChange === vin.vout) {
			return parent;
		}
	}

	return null;
}

async function gatherLinkedSignatures(startTx, startTxInputs, fetchTxWithInputs, maxHops) {
	const result = { low: 0, high: 0, linkedTxids: [] };
	if (typeof fetchTxWithInputs !== "function" || !startTx || !startTx.txid) {
		return result;
	}

	const seen = new Set([startTx.txid]);
	let curTx = startTx;
	let curInputs = startTxInputs;

	for (let hop = 0; hop < maxHops; hop++) {
		let parent = null;
		try {
			parent = await findSelfChangeParent(curTx, curInputs, fetchTxWithInputs, seen);
		} catch (err) {
			break;
		}

		if (!parent) {
			break;
		}

		const stats = ecdsaSignatureStats(normalize(parent.tx, parent.txInputs).inputs);
		result.low += stats.lowR;
		result.high += stats.highR;
		result.linkedTxids.push(parent.tx.txid);

		seen.add(parent.tx.txid);
		curTx = parent.tx;
		curInputs = parent.txInputs;
	}

	return result;
}

module.exports = {
	analyzeTransaction,
	gatherLinkedSignatures,
	WALLETS
};
