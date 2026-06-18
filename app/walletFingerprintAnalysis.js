"use strict";

const WALLETS = [
	"Bitcoin Core", "Electrum", "Blue Wallet", "Coinbase Wallet",
	"Exodus Wallet", "Trust Wallet", "Trezor", "Ledger",
	"Sparrow", "Bull Bitcoin", "Cake Wallet", "Liana", "Nunchuk", "Wasabi"
];

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

function sigAndPubkeyHex(input) {
	if (input.type === "p2wpkh" && input.witness.length >= 2) {
		return { sig: input.witness[0], pubkey: input.witness[1] };
	}

	if (input.type === "p2pkh" && input.scriptSigAsm) {
		const parts = input.scriptSigAsm.trim().split(/\s+/);
		if (parts.length >= 2) {
			return { sig: parts[0], pubkey: parts[1] };
		}
	}

	return { sig: null, pubkey: null };
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

function analyzeTransaction(tx, txInputs, txBlockHeight, currentBlockHeight) {
	if (!tx || !tx.vin || !tx.vout || (tx.vin[0] && tx.vin[0].coinbase)) {
		return { available: false };
	}

	const { inputs, outputs } = normalize(tx, txInputs);
	const haveInputData = inputs.every((i) => i.type !== "unknown");

	let candidates = WALLETS.slice();
	const discard = (...names) => { candidates = candidates.filter((w) => !names.includes(w)); };
	const keepOnly = (...names) => { candidates = candidates.filter((w) => names.includes(w)); };

	const signals = [];
	const add = (label, value, implication, privacy) => signals.push({ label, value, implication, privacy });

	const referenceHeight = (txBlockHeight && txBlockHeight > 0) ? txBlockHeight : currentBlockHeight;

	if (tx.locktime === 0) {
		add("Anti-fee-sniping", "No (nLockTime = 0)",
			"Most wallets leave nLockTime at 0, which does not narrow much but rules out the wallets that always set it (Sparrow and Bull Bitcoin, plus Bitcoin Core and Electrum which set it most of the time).",
			null);
		discard("Bitcoin Core", "Electrum", "Sparrow", "Bull Bitcoin");
	} else {
		let detail = `nLockTime = ${tx.locktime}`;
		if (referenceHeight && referenceHeight > 0) {
			const delta = referenceHeight - tx.locktime;
			detail += (delta >= 0 && delta < 100) ? " (near chain tip)" : ` (${delta} blocks below tip)`;
		}

		add("Anti-fee-sniping", detail,
			"nLockTime set near the chain tip is the anti-fee-sniping pattern. Only wallets that do this are possible: Bitcoin Core, Electrum, Sparrow, Bull Bitcoin, Liana, Nunchuk and Wasabi.",
			"A non-zero locktime narrows the wallet to the anti-fee-sniping set.");
		keepOnly("Bitcoin Core", "Electrum", "Sparrow", "Bull Bitcoin", "Liana", "Nunchuk", "Wasabi");
	}

	if (tx.version === 1) {
		add("nVersion", "1", "Transaction version 1 is used by Trust Wallet, Trezor and Ledger.", null);
		discard("Bitcoin Core", "Electrum", "Blue Wallet", "Exodus Wallet", "Coinbase Wallet",
			"Sparrow", "Bull Bitcoin", "Cake Wallet", "Liana", "Nunchuk", "Wasabi");
	} else if (tx.version === 2) {
		add("nVersion", "2", "Version 2 rules out the wallets that still emit version-1 transactions (Ledger, Trezor, Trust).", null);
		discard("Ledger", "Trezor", "Trust Wallet");
	} else {
		add("nVersion", String(tx.version), "Non-standard transaction version.", null);
		candidates = [];
	}

	const signalsRbf = inputs.some((i) => i.sequence != null && i.sequence < 0xffffffff);
	const onlyNativeSegwitInputs = haveInputData && uniqueTypes(inputs).every((t) => t === "p2wpkh");
	if (signalsRbf) {
		add("RBF signaling", "Yes (nSequence < 0xFFFFFFFF)",
			"Opt-in Replace-By-Fee. Wallets that default to no RBF (Coinbase, Exodus, Wasabi) are ruled out.", null);
		discard("Coinbase Wallet", "Exodus Wallet", "Wasabi");
		if (haveInputData && !onlyNativeSegwitInputs) {
			discard("Blue Wallet");
		}
	} else {
		add("RBF signaling", "No (nSequence = 0xFFFFFFFF)",
			"No RBF opt-in. The wallets that always signal RBF are ruled out: Bitcoin Core, Electrum, Ledger, Trezor, Trust, Sparrow, Bull Bitcoin, Liana and Nunchuk. Wallets that default to no RBF remain possible: Coinbase, Exodus, Wasabi, Cake (when spending unconfirmed coins), and Blue Wallet for its legacy, P2SH and taproot wallets.",
			null);
		discard("Bitcoin Core", "Electrum", "Ledger", "Trezor", "Trust Wallet",
			"Sparrow", "Bull Bitcoin", "Liana", "Nunchuk");
		if (onlyNativeSegwitInputs) {
			discard("Blue Wallet");
		}
	}

	const inTypes = uniqueTypes(inputs);
	if (haveInputData) {
		if (inTypes.length > 1) {
			add("Input script types", inTypes.join(", "),
				"Spending more than one address type in one transaction is uncommon; most wallets use a single type.",
				"Mixing input types both fingerprints the wallet and links otherwise-separate address types to one owner.");
			discard("Exodus Wallet", "Electrum", "Blue Wallet", "Ledger", "Trezor", "Trust Wallet",
				"Sparrow", "Liana");
		} else {
			add("Input script types", inTypes[0] || "n/a", "All inputs share one script type.", null);
		}

		if (compressedKeysOnly(inputs)) {
			add("Public keys", "Compressed", "Compressed ECDSA public keys (standard for all modern wallets).", null);
		} else {
			add("Public keys", "Uncompressed key present",
				"Uncompressed public keys are legacy behavior and rare today.",
				"An uncompressed key is a strong, unusual fingerprint.");
			candidates = [];
		}

		const sigStats = ecdsaSignatureStats(inputs);
		if (sigStats.examined > 0) {
			if (sigStats.highR > 0) {
				add("Low-R grinding", `No (${sigStats.highR} of ${sigStats.examined} ECDSA signature(s) have a 33-byte R value)`,
					"A wallet that grinds for low-R signatures would never produce a high-R one, so a high-R signature rules out the grinding wallets (Bitcoin Core, Electrum, Sparrow, Bull Bitcoin, Liana).",
					null);
				discard("Bitcoin Core", "Electrum", "Sparrow", "Bull Bitcoin", "Liana");
			} else {
				add("Low-R grinding", `All ${sigStats.examined} ECDSA signature(s) are low-R (32-byte R or smaller)`,
					`A non-grinding wallet still produces a low-R signature about half the time, so this is weak evidence (roughly 1 in ${Math.pow(2, sigStats.examined)}). Only consistent low-R across many signatures, in this transaction and related ones, indicates deliberate grinding (Bitcoin Core, Electrum).`,
					null);
			}
		}
	}

	const outTypes = outputs.map((o) => o.type);
	if (outTypes.includes("op_return")) {
		add("OP_RETURN output", "Yes",
			"This transaction embeds data in an OP_RETURN output, which several wallets never create.", null);
		discard("Coinbase Wallet", "Exodus Wallet", "Blue Wallet", "Ledger", "Trust Wallet",
			"Bull Bitcoin", "Liana", "Wasabi");
	}

	if (outputs.length > 2) {
		add("Outputs", `${outputs.length} (batched)`,
			"More than two outputs (batched payment) is something several single-recipient wallets never do.", null);
		discard("Coinbase Wallet", "Exodus Wallet", "Ledger", "Trust Wallet");
	}

	const outBip69 = bip69OutputsSorted(outputs);
	if (outputs.length > 1) {
		if (outBip69) {
			add("Output ordering", "BIP-69 (lexicographic)",
				"Outputs are sorted per BIP-69. Deterministic ordering is itself a fingerprint; only some wallets do it.", null);
		} else {
			add("Output ordering", "Not BIP-69",
				"Outputs are not in BIP-69 order, ruling out wallets that always sort (Electrum, Trezor).", null);
			discard("Electrum", "Trezor");
		}
	}

	if (inputs.length > 1) {
		if (bip69InputsSorted(inputs)) {
			add("Input ordering", "BIP-69 (lexicographic)", "Inputs are sorted per BIP-69.", null);
		} else {
			add("Input ordering", "Not BIP-69",
				"Inputs are not in BIP-69 order, ruling out wallets that always sort (Electrum, Trezor).", null);
			discard("Electrum", "Trezor");
		}
	}

	if (haveInputData) {
		const reuse = addressReuse(inputs, outputs);
		if (reuse) {
			add("Address reuse", "Yes (an output reuses an input address)",
				"Paying back to an address that was just spent. Most modern wallets avoid this.",
				"Address reuse directly links transactions and is one of the most damaging privacy leaks.");
			discard("Coinbase Wallet", "Bitcoin Core", "Electrum", "Blue Wallet", "Ledger", "Trezor",
				"Sparrow", "Bull Bitcoin", "Cake Wallet", "Liana", "Nunchuk", "Wasabi");
		} else {
			add("Address reuse", "No", "No input address is reused as an output.", null);
			discard("Exodus Wallet", "Trust Wallet");
		}

		const changeIndex = getChangeIndex(inputs, outputs);
		if (changeIndex >= 0) {
			const isLast = changeIndex === outputs.length - 1;
			add("Detected change output", `index ${changeIndex}${isLast ? " (last)" : " (not last)"}`,
				"Heuristic change detection (single matching script type / reused address / non-round amount).",
				"A predictable change position lets an observer separate the payment from the change.");
			if (!isLast) {
				discard("Ledger", "Blue Wallet", "Coinbase Wallet",
					"Sparrow", "Bull Bitcoin", "Cake Wallet", "Liana", "Wasabi");
			}

			const changeType = outputs[changeIndex].type;
			const otherOutputTypes = outputs.filter((_, i) => i !== changeIndex).map((o) => o.type);
			const matchesInput = inTypes.includes(changeType);
			const matchesOutput = otherOutputTypes.includes(changeType);
			if (matchesOutput && !matchesInput) {
				add("Change type", "Matches the payment output type",
					"Bitcoin Core derives change matching the payment type; other wallets match the input type.", null);
				keepOnly("Bitcoin Core");
			} else if (matchesInput && !matchesOutput) {
				add("Change type", "Matches the input type",
					"Change script type follows the inputs, which is what most non-Core wallets do.", null);
				discard("Bitcoin Core");
			}
		}
	}

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

module.exports = {
	analyzeTransaction,
	WALLETS
};
