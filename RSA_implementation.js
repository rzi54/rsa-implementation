/**
 * ----------------------------------------------------------------------------
 * @project     Cryptographie Asymétrique – Chiffrement RSA
 * @author      Randy LUZI
 * @contact     rl.54.pro.info@gmail.com
 * @date        05/07/2025
 * @language    JavaScript pur (ES6), sans dépendances externes (sauf pour la génération de graines)
 * ----------------------------------------------------------------------------
 * @description
 * Ce code implémente les primitives cryptographiques RSA asymétriques suivantes :
 *   - Génération sécurisée de paires de clés RSA à partir de safe primes
 *   - Chiffrement et déchiffrement RSA avec rembourrage OAEP
 *   - Signature numérique RSA avec le schéma probabiliste PSS
 *
 * L’implémentation repose sur des notions fondamentales d’arithmétique modulaire :
 *   - Algorithme d’Euclide étendu (EGCD) pour le calcul d’inverse modulaire
 *   - Test de primalité probabiliste de Miller-Rabin
 *   - Utilisation de nombres premiers sûrs (safe primes) pour la robustesse des clés
 *   - Théorème des restes chinois (CRT) pour accélérer les opérations modulaires
 *
 * @technical
 *   - Générateur de nombres pseudo-aléatoires : Blum Blum Shub (BBS)
 *   - Rembourrage pour le chiffrement : OAEP (avec hachage SHA-256)
 *   - Rembourrage pour la signature : PSS (avec hachage SHA-256)
 *   - Déchiffrement optimisé avec CRT, incluant un blinding pour contrer les attaques par canaux auxiliaires
 *
 * @note
 * Ce module est totalement autonome et peut être utilisé dans n’importe quel
 * environnement JavaScript (navigateur, Node.js, React Native, etc.).
 * Il ne dépend d’aucune bibliothèque tierce, à l’exception d’éventuels modules
 * pour la génération de graines cryptographiquement sûres.
 *
 * @license MIT
 * ----------------------------------------------------------------------------
 */

"use strict"; // Active le mode strict de JavaScript pour une exécution plus sécurisée et stricte du code

// ----------------------------------------------------------------
// ----------------------------------------------------------------
// ---------------------------------------------------------------- Génération de graines (cryptographiquement sûr) pour Node.js.

// Génère une graine cryptographiquement sûre (256 bits) dans Node.js
function generateSecureSeedNode(bytes) {
    const crypto = require('crypto');
    const seedHex = crypto.randomBytes(bytes).toString('hex');
    return BigInt('0x' + seedHex);
}

// Exemple d'utilisation
// const seedNode = generateSecureSeedNode();
// console.log("Graine générée (Node.js):", seedNode);

// ----------------------------------------------------------------
// ----------------------------------------------------------------
// ---------------------------------------------------------------- Génération de graines (cryptographiquement sûr) pour Navigateur.

/*
// Génère une graine cryptographiquement sûre dans un navigateur
function generateSecureSeedBrowser(bytes) {

const array = new Uint32Array(bytes)
window.crypto.getRandomValues(array);

let seed = 0n;
for (let i = 0; i < array.length; i++) {
seed = (seed << 32n) + BigInt(array[i]);
}

return seed;
}

// Exemple d'utilisation
const seedBrowser = generateSecureSeedBrowser();
console.log("Graine générée (navigateur):", seedBrowser);
 */

// ----------------------------------------------------------------
// ----------------------------------------------------------------
// ---------------------------------------------------------------- Génération de graines (cryptographiquement sûr) pour React Native.

/*
// Veillez à installer la dépendance : npm install react-native-get-random-values
// Veillez à importer la dépendance : import 'react-native-get-random-values';

// Génère une graine cryptographiquement sûre pour React Native
function generateSecureSeedReactNative(bytes) {

const array = new Uint32Array(bytes);
crypto.getRandomValues(array);

let seed = 0n;
for (let i = 0; i < array.length; i++) {
seed = (seed << 32n) + BigInt(array[i]);
}

return seed;
}

// Exemple d'utilisation
const seedRN = generateSecureSeedReactNative();
console.log("Graine générée (React Native):", seedRN);
 */

// ----------------------------------------------------------------
// ----------------------------------------------------------------
// ---------------------------------------------------------------- Class BBS, RSA, MillerRabin, PrimeAndGenerator

/**
 * Classe Hash
 *
 * Fournit une implémentation manuelle des algorithmes de hachage SHA-256 et SHA-512,
 * basés sur la spécification FIPS PUB 180-4.
 *
 * Ne dépend d’aucune bibliothèque externe.
 *
 * Permet de générer des condensés cryptographiques de 256 ou 512 bits,
 * encodés en hexadécimal, à partir de chaînes de caractères ASCII.
 *
 * Ne sont pas de ma main.
 */
class Hash {

    /** Algorithme de hachage SHA512.
     *
     *	@param {String ASCII} str - une chaine de caractères ASCII.
     *	@return {String HEX} - une chaine de caractères héxadécimale longue de 128 caractères.
     *
     *	@author unknow
     */
    static sha512(str) {

        function int64(msint_32, lsint_32) {
            this.highOrder = msint_32;
            this.lowOrder = lsint_32;
        };

        var H = [new int64(0x6a09e667, 0xf3bcc908), new int64(0xbb67ae85, 0x84caa73b),
            new int64(0x3c6ef372, 0xfe94f82b), new int64(0xa54ff53a, 0x5f1d36f1),
            new int64(0x510e527f, 0xade682d1), new int64(0x9b05688c, 0x2b3e6c1f),
            new int64(0x1f83d9ab, 0xfb41bd6b), new int64(0x5be0cd19, 0x137e2179)];

        var K = [new int64(0x428a2f98, 0xd728ae22), new int64(0x71374491, 0x23ef65cd),
            new int64(0xb5c0fbcf, 0xec4d3b2f), new int64(0xe9b5dba5, 0x8189dbbc),
            new int64(0x3956c25b, 0xf348b538), new int64(0x59f111f1, 0xb605d019),
            new int64(0x923f82a4, 0xaf194f9b), new int64(0xab1c5ed5, 0xda6d8118),
            new int64(0xd807aa98, 0xa3030242), new int64(0x12835b01, 0x45706fbe),
            new int64(0x243185be, 0x4ee4b28c), new int64(0x550c7dc3, 0xd5ffb4e2),
            new int64(0x72be5d74, 0xf27b896f), new int64(0x80deb1fe, 0x3b1696b1),
            new int64(0x9bdc06a7, 0x25c71235), new int64(0xc19bf174, 0xcf692694),
            new int64(0xe49b69c1, 0x9ef14ad2), new int64(0xefbe4786, 0x384f25e3),
            new int64(0x0fc19dc6, 0x8b8cd5b5), new int64(0x240ca1cc, 0x77ac9c65),
            new int64(0x2de92c6f, 0x592b0275), new int64(0x4a7484aa, 0x6ea6e483),
            new int64(0x5cb0a9dc, 0xbd41fbd4), new int64(0x76f988da, 0x831153b5),
            new int64(0x983e5152, 0xee66dfab), new int64(0xa831c66d, 0x2db43210),
            new int64(0xb00327c8, 0x98fb213f), new int64(0xbf597fc7, 0xbeef0ee4),
            new int64(0xc6e00bf3, 0x3da88fc2), new int64(0xd5a79147, 0x930aa725),
            new int64(0x06ca6351, 0xe003826f), new int64(0x14292967, 0x0a0e6e70),
            new int64(0x27b70a85, 0x46d22ffc), new int64(0x2e1b2138, 0x5c26c926),
            new int64(0x4d2c6dfc, 0x5ac42aed), new int64(0x53380d13, 0x9d95b3df),
            new int64(0x650a7354, 0x8baf63de), new int64(0x766a0abb, 0x3c77b2a8),
            new int64(0x81c2c92e, 0x47edaee6), new int64(0x92722c85, 0x1482353b),
            new int64(0xa2bfe8a1, 0x4cf10364), new int64(0xa81a664b, 0xbc423001),
            new int64(0xc24b8b70, 0xd0f89791), new int64(0xc76c51a3, 0x0654be30),
            new int64(0xd192e819, 0xd6ef5218), new int64(0xd6990624, 0x5565a910),
            new int64(0xf40e3585, 0x5771202a), new int64(0x106aa070, 0x32bbd1b8),
            new int64(0x19a4c116, 0xb8d2d0c8), new int64(0x1e376c08, 0x5141ab53),
            new int64(0x2748774c, 0xdf8eeb99), new int64(0x34b0bcb5, 0xe19b48a8),
            new int64(0x391c0cb3, 0xc5c95a63), new int64(0x4ed8aa4a, 0xe3418acb),
            new int64(0x5b9cca4f, 0x7763e373), new int64(0x682e6ff3, 0xd6b2b8a3),
            new int64(0x748f82ee, 0x5defb2fc), new int64(0x78a5636f, 0x43172f60),
            new int64(0x84c87814, 0xa1f0ab72), new int64(0x8cc70208, 0x1a6439ec),
            new int64(0x90befffa, 0x23631e28), new int64(0xa4506ceb, 0xde82bde9),
            new int64(0xbef9a3f7, 0xb2c67915), new int64(0xc67178f2, 0xe372532b),
            new int64(0xca273ece, 0xea26619c), new int64(0xd186b8c7, 0x21c0c207),
            new int64(0xeada7dd6, 0xcde0eb1e), new int64(0xf57d4f7f, 0xee6ed178),
            new int64(0x06f067aa, 0x72176fba), new int64(0x0a637dc5, 0xa2c898a6),
            new int64(0x113f9804, 0xbef90dae), new int64(0x1b710b35, 0x131c471b),
            new int64(0x28db77f5, 0x23047d84), new int64(0x32caab7b, 0x40c72493),
            new int64(0x3c9ebe0a, 0x15c9bebc), new int64(0x431d67c4, 0x9c100d4c),
            new int64(0x4cc5d4be, 0xcb3e42b6), new int64(0x597f299c, 0xfc657e2a),
            new int64(0x5fcb6fab, 0x3ad6faec), new int64(0x6c44198c, 0x4a475817)];

        var W = new Array(64);
        var a,
        b,
        c,
        d,
        e,
        f,
        g,
        h,
        i,
        j;
        var T1,
        T2;
        var charsize = 8;

        function utf8_encode(str) {
            return unescape(encodeURIComponent(str));
        };

        function str2binb(str) {
            var bin = [];
            var mask = (1 << charsize) - 1;
            var len = str.length * charsize;

            for (let i = 0; i < len; i += charsize) {
                bin[i >> 5] |= (str.charCodeAt(i / charsize) & mask) << (32 - charsize - (i % 32));
            };

            return bin;
        };

        function binb2hex(binarray) {
            var hex_tab = '0123456789abcdef';
            var str = '';
            var length = binarray.length * 4;
            var srcByte;

            for (let i = 0; i < length; i += 1) {
                srcByte = binarray[i >> 2] >> ((3 - (i % 4)) * 8);
                str += hex_tab.charAt((srcByte >> 4) & 0xF) + hex_tab.charAt(srcByte & 0xF);
            };

            return str;
        };

        function safe_add_2(x, y) {
            var lsw,
            msw,
            lowOrder,
            highOrder;

            lsw = (x.lowOrder & 0xFFFF) + (y.lowOrder & 0xFFFF);
            msw = (x.lowOrder >>> 16) + (y.lowOrder >>> 16) + (lsw >>> 16);
            lowOrder = ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);

            lsw = (x.highOrder & 0xFFFF) + (y.highOrder & 0xFFFF) + (msw >>> 16);
            msw = (x.highOrder >>> 16) + (y.highOrder >>> 16) + (lsw >>> 16);
            highOrder = ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);

            return new int64(highOrder, lowOrder);
        };

        function safe_add_4(a, b, c, d) {
            var lsw,
            msw,
            lowOrder,
            highOrder;

            lsw = (a.lowOrder & 0xFFFF) + (b.lowOrder & 0xFFFF) + (c.lowOrder & 0xFFFF) + (d.lowOrder & 0xFFFF);
            msw = (a.lowOrder >>> 16) + (b.lowOrder >>> 16) + (c.lowOrder >>> 16) + (d.lowOrder >>> 16) + (lsw >>> 16);
            lowOrder = ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);

            lsw = (a.highOrder & 0xFFFF) + (b.highOrder & 0xFFFF) + (c.highOrder & 0xFFFF) + (d.highOrder & 0xFFFF) + (msw >>> 16);
            msw = (a.highOrder >>> 16) + (b.highOrder >>> 16) + (c.highOrder >>> 16) + (d.highOrder >>> 16) + (lsw >>> 16);
            highOrder = ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);

            return new int64(highOrder, lowOrder);
        };

        function safe_add_5(a, b, c, d, e) {
            var lsw,
            msw,
            lowOrder,
            highOrder;

            lsw = (a.lowOrder & 0xFFFF) + (b.lowOrder & 0xFFFF) + (c.lowOrder & 0xFFFF) + (d.lowOrder & 0xFFFF) + (e.lowOrder & 0xFFFF);
            msw = (a.lowOrder >>> 16) + (b.lowOrder >>> 16) + (c.lowOrder >>> 16) + (d.lowOrder >>> 16) + (e.lowOrder >>> 16) + (lsw >>> 16);
            lowOrder = ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);

            lsw = (a.highOrder & 0xFFFF) + (b.highOrder & 0xFFFF) + (c.highOrder & 0xFFFF) + (d.highOrder & 0xFFFF) + (e.highOrder & 0xFFFF) + (msw >>> 16);
            msw = (a.highOrder >>> 16) + (b.highOrder >>> 16) + (c.highOrder >>> 16) + (d.highOrder >>> 16) + (e.highOrder >>> 16) + (lsw >>> 16);
            highOrder = ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);

            return new int64(highOrder, lowOrder);
        };

        function maj(x, y, z) {
            return new int64(
                (x.highOrder & y.highOrder) ^ (x.highOrder & z.highOrder) ^ (y.highOrder & z.highOrder),
                (x.lowOrder & y.lowOrder) ^ (x.lowOrder & z.lowOrder) ^ (y.lowOrder & z.lowOrder));
        };

        function ch(x, y, z) {
            return new int64(
                (x.highOrder & y.highOrder) ^ (~x.highOrder & z.highOrder),
                (x.lowOrder & y.lowOrder) ^ (~x.lowOrder & z.lowOrder));
        };

        function rotr(x, n) {
            if (n <= 32) {
                return new int64(
                    (x.highOrder >>> n) | (x.lowOrder << (32 - n)),
                    (x.lowOrder >>> n) | (x.highOrder << (32 - n)));
            } else {
                return new int64(
                    (x.lowOrder >>> n) | (x.highOrder << (32 - n)),
                    (x.highOrder >>> n) | (x.lowOrder << (32 - n)));
            };
        };

        function sigma0(x) {
            var rotr28 = rotr(x, 28);
            var rotr34 = rotr(x, 34);
            var rotr39 = rotr(x, 39);

            return new int64(
                rotr28.highOrder ^ rotr34.highOrder ^ rotr39.highOrder,
                rotr28.lowOrder ^ rotr34.lowOrder ^ rotr39.lowOrder);
        };

        function sigma1(x) {
            var rotr14 = rotr(x, 14);
            var rotr18 = rotr(x, 18);
            var rotr41 = rotr(x, 41);

            return new int64(
                rotr14.highOrder ^ rotr18.highOrder ^ rotr41.highOrder,
                rotr14.lowOrder ^ rotr18.lowOrder ^ rotr41.lowOrder);
        };

        function gamma0(x) {
            var rotr1 = rotr(x, 1),
            rotr8 = rotr(x, 8),
            shr7 = shr(x, 7);

            return new int64(
                rotr1.highOrder ^ rotr8.highOrder ^ shr7.highOrder,
                rotr1.lowOrder ^ rotr8.lowOrder ^ shr7.lowOrder);
        };

        function gamma1(x) {
            var rotr19 = rotr(x, 19);
            var rotr61 = rotr(x, 61);
            var shr6 = shr(x, 6);

            return new int64(
                rotr19.highOrder ^ rotr61.highOrder ^ shr6.highOrder,
                rotr19.lowOrder ^ rotr61.lowOrder ^ shr6.lowOrder);
        };

        function shr(x, n) {
            if (n <= 32) {
                return new int64(
                    x.highOrder >>> n,
                    x.lowOrder >>> n | (x.highOrder << (32 - n)));
            } else {
                return new int64(
                    0,
                    x.highOrder << (32 - n));
            };
        };

        str = utf8_encode(str);
        let strlen = str.length * charsize;
        str = str2binb(str);

        str[strlen >> 5] |= 0x80 << (24 - strlen % 32);
        str[(((strlen + 128) >> 10) << 5) + 31] = strlen;

        for (let i = 0; i < str.length; i += 32) {
            a = H[0];
            b = H[1];
            c = H[2];
            d = H[3];
            e = H[4];
            f = H[5];
            g = H[6];
            h = H[7];

            for (var j = 0; j < 80; j++) {
                if (j < 16) {
                    W[j] = new int64(str[j * 2 + i], str[j * 2 + i + 1]);
                } else {
                    W[j] = safe_add_4(gamma1(W[j - 2]), W[j - 7], gamma0(W[j - 15]), W[j - 16]);
                };

                T1 = safe_add_5(h, sigma1(e), ch(e, f, g), K[j], W[j]);
                T2 = safe_add_2(sigma0(a), maj(a, b, c));
                h = g;
                g = f;
                f = e;
                e = safe_add_2(d, T1);
                d = c;
                c = b;
                b = a;
                a = safe_add_2(T1, T2);
            };

            H[0] = safe_add_2(a, H[0]);
            H[1] = safe_add_2(b, H[1]);
            H[2] = safe_add_2(c, H[2]);
            H[3] = safe_add_2(d, H[3]);
            H[4] = safe_add_2(e, H[4]);
            H[5] = safe_add_2(f, H[5]);
            H[6] = safe_add_2(g, H[6]);
            H[7] = safe_add_2(h, H[7]);
        };

        var binarray = [];
        for (let i = 0; i < H.length; i++) {
            binarray.push(H[i].highOrder);
            binarray.push(H[i].lowOrder);
        };
        return binb2hex(binarray);
    };

    /** Algorithme de hachage SHA256.
     *
     *	@param {String ASCII} str - une chaine de caractères ASCII.
     *	@return {String HEX} - une chaine de caractères héxadécimale longue de 64 caractères.
     *
     *	@author unknow
     */
    static sha256(ascii) {
        function rightRotate(value, amount) {
            return (value >>> amount) | (value << (32 - amount));
        };

        var mathPow = Math.pow;
        var maxWord = mathPow(2, 32);
        var lengthProperty = 'length'
            let i,
        j; // Used as a counter across the whole file
        var result = ''

            var words = [];
        var asciiBitLength = ascii[lengthProperty] * 8;

        //* caching results is optional-remove/add slash from front of this line to toggle
        // Initial hash value: first 32 bits of the fractional parts of the square roots of the first 8 primes
        // (we actually calculate the first 64, but extra values are just ignored)
        var hash = Hash.sha256.h = Hash.sha256.h || [];
        // Round constants: first 32 bits of the fractional parts of the cube roots of the first 64 primes
        var k = Hash.sha256.k = Hash.sha256.k || [];
        var primeCounter = k[lengthProperty];
        /*/
        var hash = [],
        k = [];
        var primeCounter = 0;
        //*/

        var isComposite = {};
        for (var candidate = 2; primeCounter < 64; candidate++) {
            if (!isComposite[candidate]) {
                for (i = 0; i < 313; i += candidate) {
                    isComposite[i] = candidate;
                };
                hash[primeCounter] = (mathPow(candidate, .5) * maxWord) | 0;
                k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
            };
        };

        ascii += '\x80' // Append Ƈ' bit (plus zero padding)
        while (ascii[lengthProperty] % 64 - 56)
            ascii += '\x00' // More zero padding
            for (i = 0; i < ascii[lengthProperty]; i++) {
                j = ascii.charCodeAt(i);
                if (j >> 8)
                    return; // ASCII check: only accept characters in range 0-255
                words[i >> 2] |= j << ((3 - i) % 4) * 8;
            };
        words[words[lengthProperty]] = ((asciiBitLength / maxWord) | 0);
        words[words[lengthProperty]] = (asciiBitLength);

        // process each chunk
        for (j = 0; j < words[lengthProperty]; ) {
            var w = words.slice(j, j += 16); // The message is expanded into 64 words as part of the iteration
            var oldHash = hash;
            // This is now the undefinedworking hash", often labelled as variables a...g
            // (we have to truncate as well, otherwise extra entries at the end accumulate
            hash = hash.slice(0, 8);

            for (i = 0; i < 64; i++) {
                var i2 = i + j;
                // Expand the message into 64 words
                // Used below if
                var w15 = w[i - 15],
                w2 = w[i - 2];

                // Iterate
                var a = hash[0],
                e = hash[4];
                var temp1 = hash[7]
                     + (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)) // S1
                     + ((e & hash[5]) ^ ((~e) & hash[6])) // ch
                    +k[i]
                    // Expand the message schedule if needed
                     + (w[i] = (i < 16) ? w[i] : (
                            w[i - 16]
                             + (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3)) // s0
                            +w[i - 7]
                             + (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10)) // s1
                        ) | 0);
                // This is only used once, so *could* be moved below, but it only saves 4 bytes and makes things unreadble
                var temp2 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)) // S0
                 + ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2])); // maj

                hash = [(temp1 + temp2) | 0].concat(hash); // We don't bother trimming off the extra ones, they're harmless as long as we're truncating when we do the slice()
                hash[4] = (hash[4] + temp1) | 0;
            };

            for (i = 0; i < 8; i++) {
                hash[i] = (hash[i] + oldHash[i]) | 0;
            };
        };

        for (i = 0; i < 8; i++) {
            for (j = 3; j + 1; j--) {
                var b = (hash[i] >> (j * 8)) & 255;
                result += ((b < 16) ? 0 : '') + b.toString(16);
            };
        };
        return result;
    };

}

/**
 * Classe MillerRabin
 *
 * Fournit un test de primalité probabiliste basé sur le test de Miller-Rabin.
 * Utilise des bases déterministes (bases de Lucas-Meyer) pour améliorer l'efficacité
 * du test tout en maintenant une bonne fiabilité pour des entiers usuels.
 *
 */
class MillerRabin {

    /**
     * Test de primalité probabiliste basé sur le test de Miller-Rabin.
     *
     * @param {BigInt} n - Le nombre à tester (doit être un entier positif ≥ 2).
     * @param {number} [k=16] - Nombre de bases utilisées pour le test (plus k est grand, plus le test est fiable).
     * @returns {boolean} - Retourne true si n est probablement premier, false sinon.
     */
    static isPrime(n, k = 16) {
        if (n === 2n || n === 3n)
            return true;
        if (n < 2n || n % 2n === 0n)
            return false;

        let r = 0n;
        let d = n - 1n;
        while (d % 2n === 0n) {
            d /= 2n;
            r++;
        }

        const bases = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n];
        for (let i = 0; i < k; i++) {
            const a = bases[i % bases.length];
            if (a >= n - 2n)
                continue;
            let x = RSA.modPow(a, d, n);
            if (x === 1n || x === n - 1n)
                continue;

            let continueOuter = false;
            for (let j = 0n; j < r - 1n; j++) {
                x = RSA.modPow(x, 2n, n);
                if (x === n - 1n) {
                    continueOuter = true;
                    break;
                }
            }
            if (continueOuter)
                continue;

            return false;
        }
        return true;
    }
}

/**
 * Classe BlumBlumShub
 *
 * Générateur pseudo-aléatoire cryptographique basé sur l'algorithme Blum Blum Shub.
 * Utilise des entiers premiers de la forme 3 mod 4 pour une sécurité renforcée.
 *
 */
class BlumBlumShub {

    /**
     * Initialise le générateur avec une graine et deux entiers premiers.
     *
     * @param {BigInt} seed - Graine de départ.
     * @param {BigInt} p - Premier nombre premier tel que p ≡ 3 (mod 4).
     * @param {BigInt} q - Second nombre premier tel que q ≡ 3 (mod 4).
     * @param {number} [bits=256] - Nombre de bits de sortie générés.
     */
    constructor(seed, p, q, bits = 256) {
        this.p = p;
        this.q = q;
        this.m = p * q;
        this.bits = bits;
        this.state = seed % this.m;
        if (this.state === 0n)
            this.state = 1n;
    }

    /**
     * Génère le prochain bit pseudo-aléatoire.
     *
     * @returns {BigInt} - Un bit (0n ou 1n).
     */
    nextBit() {
        this.state = (this.state * this.state) % this.m;
        return this.state & 1n;
    }

    /**
     * Génère une séquence de bits pseudo-aléatoires, avec des contraintes
     * pour obtenir un nombre impair, de poids fort activé et congru à 3 modulo 4.
     *
     * @param {number} n - Nombre de bits à générer.
     * @returns {BigInt} - Un entier pseudo-aléatoire de n bits conforme aux critères.
     */
    nextBits(n) {
        let result = 0n;
        for (let i = 0; i < n; i++) {
            result = (result << 1n) | this.nextBit();
        }
        result = result | (1n << BigInt(n - 1));
        result = result | 1n;
        result = result - (result % 4n) + 3n;
        return result;
    }

    // --- Fonctions générales

    /**
     * Génère un nombre premier aléatoire de n bits vérifiant ≡ 3 (mod 4).
     *
     * @param {BigInt} seed - Graine de départ.
     * @param {number} bits - Taille en bits du nombre premier.
     * @param {number} [maxTries=1000] - Nombre maximal d’essais.
     * @returns {BigInt} - Nombre premier généré.
     *
     * @throws {Error} - Si aucun nombre valide n’a été trouvé.
     *
     * @author Randy LUZI
     */
    static generatePrime3Mod4(seed, bits, maxTries = 1000) {
        const smallP = 499n;
        const smallQ = 547n;

        for (let tries = 0; tries < maxTries; tries++) {
            const prng = new BlumBlumShub(seed + BigInt(tries), smallP, smallQ, bits);
            const candidate = prng.nextBits(bits);

            if (BlumBlumShub.isPrimeMillerRabin(candidate, 16) && candidate % 4n === 3n) {
                return candidate;
            }
        }
        throw new Error("Echec : impossible de générer un premier 3 mod 4 après trop d'essais");
    }

    /**
     * Génère un seul nombre premier de n bits vérifiant ≡ 3 (mod 4).
     * Appelle la fonction `generatePrime3Mod4`.
     *
     * @param {BigInt} seed - Graine utilisée pour générer le nombre.
     * @param {number} bits - Nombre de bits souhaité.
     * @returns {BigInt} - Nombre premier.
     */
    static generatePrimes3Mod4(seed, bits) {
        const maxSeedIncrements = 1000;
        let k;

        k = BlumBlumShub.generatePrime3Mod4(seed, bits);

        return k;
    }

    /**
     * Effectue une exponentiation modulaire efficace.
     *
     * @param {BigInt} base - Base.
     * @param {BigInt} exp - Exposant.
     * @param {BigInt} mod - Modulo.
     * @returns {BigInt} - Résultat de (base^exp) mod mod.
     */
    static modPow(base, exp, mod) {
        let result = 1n;
        base = base % mod;
        while (exp > 0n) {
            if (exp % 2n === 1n) {
                result = (result * base) % mod;
            }
            base = (base * base) % mod;
            exp /= 2n;
        }
        return result;
    }

    /**
     * Implémente le test de primalité probabiliste de Miller-Rabin,
     * version Lucas-Meyer (avec bases fixes).
     *
     * @param {BigInt} n - Nombre à tester.
     * @param {number} [k=16] - Nombre d’itérations.
     * @returns {boolean} - True si probablement premier, false sinon.
     */
    static isPrimeMillerRabin(n, k = 16) {
        if (n === 2n || n === 3n)
            return true;
        if (n < 2n || n % 2n === 0n)
            return false;

        let r = 0n;
        let d = n - 1n;
        while (d % 2n === 0n) {
            d /= 2n;
            r++;
        }

        const bases = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n];
        for (let i = 0; i < k; i++) {
            const a = bases[i % bases.length];
            if (a >= n - 2n)
                continue;
            let x = RSA.modPow(a, d, n);
            if (x === 1n || x === n - 1n)
                continue;

            let continueOuter = false;
            for (let j = 0n; j < r - 1n; j++) {
                x = RSA.modPow(x, 2n, n);
                if (x === n - 1n) {
                    continueOuter = true;
                    break;
                }
            }
            if (continueOuter)
                continue;

            return false;
        }
        return true;
    }
}

/**
 * Classe RSA : Implémentation complète d’un système de chiffrement RSA sécurisé avec padding OAEP, blinding, CRT et signatures PSS.
 *
 * Fonctionnalités principales :
 * - Génération sécurisée des clés RSA (p, q, n, e, d) avec vérifications renforcées.
 * - Padding OAEP pour un chiffrement probabiliste sécurisé, empêchant les attaques à texte clair choisi.
 * - Signature et vérification RSA avec schéma PSS (Probabilistic Signature Scheme) pour des signatures robustes.
 * - Chiffrement et déchiffrement RSA utilisant OAEP.
 * - Déchiffrement optimisé avec CRT (Chinese Remainder Theorem) pour accélérer le processus.
 * - Déchiffrement avec aveuglement (blinding) pour protéger contre les attaques par canaux auxiliaires.
 * - Protection contre diverses attaques sur la clé privée : Wiener, Boneh-Durfee, exposants faibles, palindromes.
 *
 * Attributs principaux :
 * - p, q : nombres premiers secrets.
 * - n = p * q : module public.
 * - e : exposant public.
 * - d : exposant privé.
 * - dp, dq : exposants privés modulo p-1 et q-1 (pour CRT).
 * - qinv : inverse modulaire de q modulo p (pour CRT).
 *
 * Notes :
 * - Le padding OAEP ajoute une couche de sécurité cryptographique en rendant le chiffrement probabiliste.
 * - Le schéma PSS fournit des signatures probabilistes robustes, réduisant la vulnérabilité aux attaques adaptatives.
 * - Les protections intégrées assurent une résistance élevée face aux attaques classiques et avancées.
 *
 */
class RSA {

    constructor() {
        this.prop_bbs_factor = 8;
    }

    /**
     * Initialise le générateur de nombres pseudo-aléatoires sécurisés (PRNG).
     * Utilise la classe SecureRandom pour assurer une bonne entropie.
     * Cette méthode doit être appelée avant toute génération de clés ou nombres aléatoires.
     */
    initPRNG() {

        this.seed = BigInt("0x" + generateSecureSeedNode(59));
        const p = BlumBlumShub.generatePrimes3Mod4(this.seed, this.bits / this.prop_bbs_factor);

        this.seed = BigInt("0x" + generateSecureSeedNode(47));
        const q = BlumBlumShub.generatePrimes3Mod4(this.seed, this.bits / this.prop_bbs_factor);

        this.seed = BigInt("0x" + generateSecureSeedNode(31));
        this.prng = new BlumBlumShub(this.seed, p, q, this.bits);

    }

    /**
     * Recherche un nombre premier selon le format demandé.
     * @param {boolean} format2pAdd1 - Si vrai, cherche un nombre premier de la forme 2p + 1.
     * @param {number} maxTries - Nombre maximal d'essais avant échec.
     * @returns {BigInt} Un nombre premier conforme aux critères.
     * @throws {Error} Si aucun nombre premier valide n'est trouvé.
     */
    findPrimeRSA(format2pAdd1 = false, maxTries = 10000) {
        for (let i = 0; i < maxTries; i++) {
            let candidate = this.prng.nextBits(this.bits);

            if (format2pAdd1) {
                // Test primalité de la forme 2p + 1
                if (RSA.isPrimeMillerRabin((2n * candidate) + 1n, 16)) {
                    return (2n * candidate) + 1n;
                }
            } else {
                // Test primalité non de la forme 2p + 1
                if (RSA.isPrimeMillerRabin(candidate, 16)) {
                    return candidate;
                }
            }
        }
        throw new Error("Impossible de trouver un nombre premier RSA après trop d'essais");
    }

    /**
     * Génère une paire de clés RSA selon le nombre de bits souhaité.
     * Applique plusieurs tests pour assurer la sécurité de l'exposant privé d.
     * @param {number} bits - Taille des clés en bits (par défaut 256).
     * @param {string} format - Format de sortie des clés ("dec", "hex", ...).
     * @returns {Object} Un objet contenant la clé publique et la clé privée.
     */
    generateKeys(bits = 1024) {

        this.bits = bits;

        this.initPRNG();

        let p,
        q,
        n,
        phi,
        d,
        e;
        e = 65537n;

        while (true) { // On boucle jusqu’à ce qu’on ait un exposant d valide

            // Génération de p
            this.seed = BigInt("0x" + generateSecureSeedNode(64));
            this.initPRNG();
            p = this.findPrimeRSA(true);

            // Génération de q
            this.seed = BigInt("0x" + generateSecureSeedNode(64));
            this.initPRNG();
            do {
                q = this.findPrimeRSA(true);
            } while (q === p || (p > q ? p - q : q - p) < 2n ** BigInt((bits / 4) | 0));

            n = p * q;
            phi = (p - 1n) * (q - 1n);

            // Vérifie que e et phi sont premiers entre eux
            if (RSA.gcd(e, phi) !== 1n)
                continue;

            // Calcul de d
            d = RSA.modInverse(e, phi);

            // 1. Attaque de Wiener : d > n^(1/4)/3
            const nRoot4 = RSA.integerRoot(n, 4n);
            if (d <= nRoot4 / 3n)
                continue;

            // 2. d > 2^(bitLength(n)/2)
            const minD = 2n ** BigInt(Math.floor(n.toString(2).length / 2));
            if (d <= minD)
                continue;

            // 3. Poids de Hamming raisonnable : au moins 25 %
            const dBin = d.toString(2);
            const hammingWeight = [...dBin].filter(x => x === '1').length;
            if (hammingWeight < dBin.length / 4)
                continue;

            // 4. Boneh–Durfee : d > n^0.3
            const nRoot10 = RSA.integerRoot(n, 10n); // n^0.1
            const nPow03 = nRoot10 ** 3n;
            if (d <= nPow03)
                continue;

            // 5. d n’est pas un palindrome (décimal ou binaire)
            const dDec = d.toString();
            const dRevDec = [...dDec].reverse().join("");
            const dRevBin = [...dBin].reverse().join("");
            if (dDec === dRevDec || dBin === dRevBin)
                continue;

            // 6. d n’a pas de motifs répétés
            function hasRepeatingPattern(str, minLength = 2, minRepeats = 3) {
                for (let len = minLength; len <= str.length / minRepeats; len++) {
                    const pattern = str.slice(0, len);
                    if (pattern.repeat(minRepeats).startsWith(str))
                        return true;
                }
                return false;
            }
            if (hasRepeatingPattern(dDec) || hasRepeatingPattern(dBin))
                continue;

            // 7. d n’est pas proche d’une puissance de deux
            function nearestPowerOf2(x) {
                const bits = x.toString(2).length;
                const lower = 2n ** BigInt(bits - 1);
                const upper = 2n ** BigInt(bits);
                // On retourne le plus proche des deux
                return (x - lower <= upper - x) ? lower : upper;
            }

            const nearestPow2 = nearestPowerOf2(d);
            const diff = d > nearestPow2 ? d - nearestPow2 : nearestPow2 - d;
            if (diff < 2n ** 16n)
                continue;

            // 8. Fin trop régulière (queue binaire)
            const tail = dBin.slice(-16);
            if (/^0+$/.test(tail) || /^1+$/.test(tail))
                continue;

            break; // d est bon
        }

        // Forger les clés
        const publicKey = {
            e,
            n,
        };

        const privateKey = {
            p,
            q,
            e,
            d,
            n,
            phi,
            dp: d % (p - 1n),
            dq: d % (q - 1n),
            qinv: RSA.modInverse(q, p),
        };

        // Conversion des clé en base 64
        const publicKeyBase64 = btoa(RSA.stringifyWithBigInt(publicKey));
        const privateKeyBase64 = btoa(RSA.stringifyWithBigInt(privateKey));

        // Retourner les clés
        return {
            publicKey: publicKeyBase64,
            privateKey: privateKeyBase64
        };
    }

    // --- Chiffrement RSA Classique

    /**
     * Chiffre un message texte avec la clé publique RSA classique.
     * @param {string} message - Le message en clair à chiffrer.
     * @param {BigInt} publicKey - La clé public.
     * @returns {BigInt} Le message chiffré sous forme d'entier.
     * @throws {Error} Si le message est trop long.
     */
    encrypt(message, publicKey) {

        publicKey = RSA.decodeKeyBase64(publicKey);
        const {
            n,
            e
        } = publicKey;

        const mBigInt = BigInt("0x" + Buffer.from(message).toString("hex"));
        if (mBigInt >= n)
            throw new Error("Message trop long");
        return RSA.modPow(mBigInt, e, n);
    }

    /**
     * Déchiffre un message chiffré avec la clé privée RSA classique.
     * @param {BigInt} cipherBigInt - Le message chiffré.
     * @param {Object} privateKey - La clé privée RSA (doit contenir d et n).
     * @returns {string} Le message en clair.
     */
    decrypt(cipherBigInt, privateKey) {

        privateKey = RSA.decodeKeyBase64(privateKey);

        const mBigInt = RSA.modPow(cipherBigInt, privateKey.d, privateKey.n);

        let hex = mBigInt.toString(16);
        if (hex.length % 2)
            hex = "0" + hex;
        const buffer = Buffer.from(hex, "hex");
        return buffer.toString("utf8");
    }

    /**
     * Déchiffrement RSA avec aveuglement pour éviter les attaques temporelles.
     * @param {BigInt} cipherBigInt - Le message chiffré.
     * @param {Object} privateKey - La clé privée RSA.
     * @returns {string} Le message déchiffré en clair.
     */
    decryptBlinding(cipherBigInt, privateKey) {

        privateKey = RSA.decodeKeyBase64(privateKey);

        const rng = new GenerateCryptoRandomNumber();
        rng.initPRNG(64); // Initialise BBS sur 512 bits
        let r = rng.nextNumber() & 0xFFFFn; // Génère un aléa r

        const mBigInt = RSA.modPow(cipherBigInt, privateKey.d + (r * privateKey.phi), privateKey.n);

        let hex = mBigInt.toString(16);
        if (hex.length % 2)
            hex = "0" + hex;
        const buffer = Buffer.from(hex, "hex");
        return buffer.toString("utf8");
    }

    /**
     * Déchiffrement RSA avec optimisation par le théorème chinois des restes (CRT).
     * Permet d’accélérer le déchiffrement.
     * @param {BigInt} cipherBigInt - Le message chiffré.
     * @param {Object} privateKey - La clé privée RSA (avec dp, dq, qinv, p, q).
     * @returns {string} Le message déchiffré en clair.
     */
    decryptCRT(cipherBigInt, privateKey) {

        privateKey = RSA.decodeKeyBase64(privateKey);

        let mp = RSA.modPow(cipherBigInt, privateKey.dp, privateKey.p);
        let mq = RSA.modPow(cipherBigInt, privateKey.dq, privateKey.q);
        let h = ((mp - mq) * privateKey.qinv) % privateKey.p;
        if (h < 0n)
            h += privateKey.p;
        let mBigInt = (mq + h * privateKey.q)

        let hex = mBigInt.toString(16);
        if (hex.length % 2)
            hex = "0" + hex;
        const buffer = Buffer.from(hex, "hex");

        return buffer.toString("utf8");
    }

    /**
     * Déchiffrement RSA combinant aveuglement et optimisation CRT.
     * @param {BigInt} cipherBigInt - Le message chiffré.
     * @param {Object} privateKey - La clé privée RSA.
     * @returns {string} Le message déchiffré.
     */
    decryptBlindingCRT(cipherBigInt, privateKey) {

        privateKey = RSA.decodeKeyBase64(privateKey);

        // Générateurs d'aléa pour le blinding
        const rngp = new GenerateCryptoRandomNumber();
        rngp.initPRNG(64);
        let rp = rngp.nextNumber() & 0xFFFFn; // 16 bits max
        if (rp === 0n)
            rp = 1n;

        const rngq = new GenerateCryptoRandomNumber();
        rngq.initPRNG(64);
        let rq = rngq.nextNumber() & 0xFFFFn;
        if (rq === 0n)
            rq = 1n;

        // Appliquer le blinding sur les exposants CRT (sans modulo !)
        const dp_ = privateKey.dp + rp * (privateKey.p - 1n);
        const dq_ = privateKey.dq + rq * (privateKey.q - 1n);

        // Calcul modulaire avec exposants "blinded"
        const mp = RSA.modPow(cipherBigInt, dp_, privateKey.p);
        const mq = RSA.modPow(cipherBigInt, dq_, privateKey.q);

        // Combinaison selon CRT
        let h = ((mp - mq) * privateKey.qinv) % privateKey.p;
        if (h < 0n)
            h += privateKey.p;

        const mBigInt = mq + h * privateKey.q;

        // Conversion en texte
        let hex = mBigInt.toString(16);
        if (hex.length % 2)
            hex = "0" + hex;
        const buffer = Buffer.from(hex, "hex");

        const utf8 = buffer.toString("utf8");

        return utf8;
    }

    // --- Chiffrement RSA OAEP

    /**
     * Chiffrement RSA avec padding OAEP.
     * @param {string} message - Le message en clair à chiffrer.
     * @param {BigInt} publicKey - La clé public.
     * @returns {BigInt} Le message chiffré sous forme d'entier.
     * @throws {Error} Si le message est trop grand pour la taille du module.
     */
    encryptOAEP(message, publicKey) {

        publicKey = RSA.decodeKeyBase64(publicKey);
        const {
            n,
            e
        } = publicKey;

        const k = Math.ceil(n.toString(2).length / 8);
        const EM = RSA.OAEPEncode(message, Buffer.alloc(0), k);
        const m = BigInt("0x" + EM.toString("hex"));
        if (m >= n)
            throw new Error("Message trop grand pour RSA");

        return RSA.modPow(m, e, n);
    }

    /**
     * Déchiffrement RSA avec padding OAEP.
     * @param {BigInt} cipherBigInt - Le message chiffré.
     * @param {Object} privateKey - La clé privée RSA.
     * @returns {string} Le message déchiffré.
     */
    decryptOAEP(cipherBigInt, privateKey) {

        privateKey = RSA.decodeKeyBase64(privateKey);

        // Déchiffrement classique
        const m = RSA.modPow(cipherBigInt, privateKey.d, privateKey.n);
        let hex = m.toString(16);
        if (hex.length % 2)
            hex = "0" + hex;

        // Décodage OAEP
        const EM = Buffer.from(hex, "hex");
        const k = Math.ceil(privateKey.n.toString(2).length / 8);
        if (EM.length < k) {
            const padded = Buffer.alloc(k);
            EM.copy(padded, k - EM.length);
            return RSA.OAEPDecode(padded, Buffer.alloc(0));
        }
        return RSA.OAEPDecode(EM, Buffer.alloc(0));
    }

    /**
     * Déchiffrement RSA avec padding OAEP et aveuglement.
     * @param {BigInt} cipherBigInt - Le message chiffré.
     * @param {Object} privateKey - La clé privée RSA.
     * @returns {string} Le message déchiffré.
     */
    decryptOAEPBlinding(cipherBigInt, privateKey) {

        privateKey = RSA.decodeKeyBase64(privateKey);

        // Aveuglement
        const rng = new GenerateCryptoRandomNumber();
        rng.initPRNG(64); // Initialise BBS sur 512 bits
        let r = rng.nextNumber() & 0xFFFFn; // Génère un aléa r
        const mBigInt = RSA.modPow(cipherBigInt, privateKey.d + (r * privateKey.phi), privateKey.n);
        let hex = mBigInt.toString(16);
        if (hex.length % 2)
            hex = "0" + hex;

        // Décodage OAEP
        const EM = Buffer.from(hex, "hex");
        const k = Math.ceil(privateKey.n.toString(2).length / 8);
        if (EM.length < k) {
            const padded = Buffer.alloc(k);
            EM.copy(padded, k - EM.length);
            return RSA.OAEPDecode(padded, Buffer.alloc(0));
        }
        return RSA.OAEPDecode(EM, Buffer.alloc(0));
    }

    /**
     * Déchiffrement RSA avec padding OAEP et optimisation CRT.
     * @param {BigInt} cipherBigInt - Le message chiffré.
     * @param {Object} privateKey - La clé privée RSA.
     * @returns {string} Le message déchiffré.
     */
    decryptOAEPCRT(cipherBigInt, privateKey) {

        privateKey = RSA.decodeKeyBase64(privateKey);

        // Optimisation CRT
        let mp = RSA.modPow(cipherBigInt, privateKey.dp, privateKey.p);
        let mq = RSA.modPow(cipherBigInt, privateKey.dq, privateKey.q);

        let h = ((mp - mq) * privateKey.qinv) % privateKey.p;
        if (h < 0n)
            h += privateKey.p;
        const mBigInt = mq + (h * privateKey.q);
        let hex = mBigInt.toString(16);
        if (hex.length % 2)
            hex = "0" + hex;

        // Décodage OAEP
        const EM = Buffer.from(hex, "hex");
        const k = Math.ceil(privateKey.n.toString(2).length / 8);
        if (EM.length < k) {
            const padded = Buffer.alloc(k);
            EM.copy(padded, k - EM.length);
            return RSA.OAEPDecode(padded, Buffer.alloc(0));
        }
        return RSA.OAEPDecode(EM, Buffer.alloc(0));
    }

    /**
     * Déchiffrement RSA avec padding OAEP, aveuglement et optimisation CRT.
     * @param {BigInt} cipherBigInt - Le message chiffré.
     * @param {Object} privateKey - La clé privée RSA.
     * @returns {string} Le message déchiffré.
     */
    decryptOAEPBlindingCRT(cipherBigInt, privateKey) {

        privateKey = RSA.decodeKeyBase64(privateKey);

        // Générateurs d'aléa pour le blinding
        const rngp = new GenerateCryptoRandomNumber();
        rngp.initPRNG(64);
        let rp = rngp.nextNumber();
        if (rp === 0n)
            rp = 1n;

        const rngq = new GenerateCryptoRandomNumber();
        rngq.initPRNG(64);
        let rq = rngq.nextNumber();
        if (rq === 0n)
            rq = 1n;

        // Blinding CRT
        const dp_ = privateKey.dp + rp * (privateKey.p - 1n);
        const dq_ = privateKey.dq + rq * (privateKey.q - 1n);

        const mp = RSA.modPow(cipherBigInt, dp_, privateKey.p);
        const mq = RSA.modPow(cipherBigInt, dq_, privateKey.q);

        let h = ((mp - mq) * privateKey.qinv) % privateKey.p;
        if (h < 0n)
            h += privateKey.p;

        const mBigInt = mq + h * privateKey.q;

        // Conversion en Buffer
        let hex = mBigInt.toString(16);
        if (hex.length % 2)
            hex = "0" + hex;
        const EM = Buffer.from(hex, "hex");

        // Calcul de la taille k (en octets)
        const k = Math.ceil(privateKey.n.toString(2).length / 8);

        // Ajoute des zéros à gauche si nécessaire (pad à gauche)
        let padded;
        if (EM.length < k) {
            padded = Buffer.alloc(k);
            EM.copy(padded, k - EM.length);
        } else {
            padded = EM;
        }

        // Décodage OAEP
        const decoded = RSA.OAEPDecode(padded, Buffer.alloc(0));

        return decoded;
    }

    // --- Fonctions OAEP

    /**
     * Convertit un entier en octet string de longueur fixe (Integer-to-Octet-String).
     * @param {bigint} value - L’entier à convertir.
     * @param {number} length - La longueur cible en octets.
     * @returns {Buffer} Buffer contenant la représentation sur length octets.
     */
    static I2OSP(value, length) {
        const result = Buffer.alloc(length);
        for (let i = length - 1; i >= 0; i--) {
            result[i] = Number(value & 0xFFn);
            value >>= 8n;
        }
        return result;
    }

    /**
     * Génère un masque de longueur maskLen à partir d’une graine seed (Mask Generation Function 1).
     * Utilise SHA-256 comme fonction de hachage.
     * @param {Buffer} seed - La graine.
     * @param {number} maskLen - La longueur du masque souhaité en octets.
     * @returns {Buffer} Le masque généré.
     */
    static MGF1(seed, maskLen) {
        const hLen = 32;
        const count = Math.ceil(maskLen / hLen);
        const T = [];

        for (let i = 0; i < count; i++) {
            const c = RSA.I2OSP(BigInt(i), 4);
            const input = Buffer.concat([seed, c]);
            const hashHex = Hash.sha256(input.toString("hex"));
            const hash = Buffer.from(hashHex, "hex");

            T.push(hash);
        }

        return Buffer.concat(T).slice(0, maskLen);
    }

    /**
     * Génère un vecteur aléatoire de taille hLen à partir du générateur BBS.
     * @param {GenerateCryptoRandomNumber} rng - Instance du générateur BBS.
     * @param {number} hLen - Nombre d’octets à générer.
     * @returns {Buffer} Buffer d’octets aléatoires.
     */
    static getSeedFromBBS(rng, hLen) {
        const seedBytes = [];
        while (seedBytes.length < hLen) {
            let rand = rng.nextNumber();
            let hex = rand.toString(16);
            if (hex.length % 2)
                hex = "0" + hex;
            const buf = Buffer.from(hex, "hex");
            seedBytes.push(...buf);
        }
        return Buffer.from(seedBytes.slice(0, hLen));
    }

    /**
     * Encode un message avec le padding OAEP.
     * @param {string|Buffer} message - Le message à encoder.
     * @param {Buffer} [label=Buffer.alloc(0)] - Label optionnel pour le hachage.
     * @param {number} k - Taille du module en octets.
     * @returns {Buffer} Message encodé selon OAEP.
     * @throws {Error} Si le message est trop long.
     */
    static OAEPEncode(message, label = Buffer.alloc(0), k) {

        const mBuf = Buffer.from(message);
        const mLen = mBuf.length;
        const hLen = 32;
        const psLen = k - mLen - 2 * hLen - 2;
        if (psLen < 0)
            throw new Error("Message trop long pour OAEP");

        const lHash = Buffer.from(Hash.sha256(label), "hex");
        const PS = Buffer.alloc(psLen, 0x00);
        const DB = Buffer.concat([lHash, PS, Buffer.from([0x01]), mBuf]);

        const rng = new GenerateCryptoRandomNumber();
        rng.initPRNG(64);
        const seed = RSA.getSeedFromBBS(rng, hLen);

        const dbMask = RSA.MGF1(seed, k - hLen - 1);
        const maskedDB = Buffer.alloc(DB.length);
        for (let i = 0; i < DB.length; i++)
            maskedDB[i] = DB[i] ^ dbMask[i];

        const seedMask = RSA.MGF1(maskedDB, hLen);
        const maskedSeed = Buffer.alloc(hLen);
        for (let i = 0; i < hLen; i++)
            maskedSeed[i] = seed[i] ^ seedMask[i];

        return Buffer.concat([Buffer.from([0x00]), maskedSeed, maskedDB]);

    }

    /**
     * Décode un message encodé avec OAEP.
     * @param {Buffer} encoded - Message encodé.
     * @param {Buffer} [label=Buffer.alloc(0)] - Label optionnel.
     * @returns {string} Message original décodé.
     * @throws {Error} Si la vérification OAEP échoue.
     */
    static OAEPDecode(encoded, label = Buffer.alloc(0)) {
        const hLen = 32;
        const Y = encoded[0];
        if (Y !== 0x00)
            throw new Error("Erreur OAEP : Y != 0x00");

        const maskedSeed = encoded.subarray(1, 1 + hLen);
        const maskedDB = encoded.subarray(1 + hLen);

        const seedMask = RSA.MGF1(maskedDB, hLen);
        const seed = Buffer.alloc(hLen);
        for (let i = 0; i < hLen; i++)
            seed[i] = maskedSeed[i] ^ seedMask[i];

        const dbMask = RSA.MGF1(seed, maskedDB.length);
        const DB = Buffer.alloc(maskedDB.length);
        for (let i = 0; i < maskedDB.length; i++)
            DB[i] = maskedDB[i] ^ dbMask[i];

        const lHash = Buffer.from(Hash.sha256(label), "hex");
        if (!DB.subarray(0, hLen).equals(lHash))
            throw new Error("Erreur OAEP : lHash");

        let i = hLen;
        while (i < DB.length && DB[i] === 0x00)
            i++;
        if (DB[i] !== 0x01)
            throw new Error("Erreur OAEP : séparateur 0x01 manquant");

        return DB.subarray(i + 1).toString("utf8");
    }

    // --- Signature RSA-PSS

    /**
     * Encode le haché du message mHashHex selon le schéma RSA-PSS.
     * Ajoute du sel, un hachage intermédiaire et applique un masque.
     * @param {string} mHashHex - Le haché SHA-256 hexadécimal du message.
     * @param {number} emLen - Longueur du message encodé souhaitée en octets.
     * @param {number} emBits - Nombre de bits effectifs du module RSA.
     * @returns {Buffer} Le message encodé prêt à être signé.
     */
    emsaPSSencode(mHashHex, emLen, emBits) {
        const hLen = 32;

        if (emLen < hLen + hLen + 2)
            throw new Error("Encoding error: intended encoded message length too short");

        const mHash = Buffer.from(mHashHex, "hex");

        // Génère un sel aléatoire de longueur hLen
        const salt = Buffer.alloc(hLen);
        const rngq = new GenerateCryptoRandomNumber();
        rngq.initPRNG(hLen * 8);
        for (let i = 0; i < hLen; i++) {
            salt[i] = Number(rngq.nextNumber() & 0xFFn);
        }

        // Concatène le préfixe, le haché du message et le sel
        const M = Buffer.concat([Buffer.alloc(8, 0), mHash, salt]);

        // H = Hash(M)
        const Hhex = Hash.sha256(M.toString("latin1"));
        const H = Buffer.from(Hhex, "hex");

        // Construction de DB = PS || 0x01 || salt
        const psLen = emLen - hLen - hLen - 2;
        if (psLen < 0)
            throw new Error("PS length negative");
        const PS = Buffer.alloc(psLen, 0x00);
        const DB = Buffer.concat([PS, Buffer.from([0x01]), salt]);

        // Masquage de DB
        const dbMask = RSA.MGF1(H, DB.length);
        const maskedDB = Buffer.alloc(DB.length);
        for (let i = 0; i < DB.length; i++) {
            maskedDB[i] = DB[i] ^ dbMask[i];
        }

        // Applique les bits inutilisés à zéro
        const unusedBits = 8 * emLen - emBits;
        if (unusedBits > 0) {
            const mask = 0xFF >> unusedBits;
            maskedDB[0] &= mask;
        }

        // Assemble le message encodé EM = maskedDB || H || 0xbc
        const EM = Buffer.concat([maskedDB, H, Buffer.from([0xbc])]);

        if (EM.length !== emLen) {
            throw new Error(`EM length incorrect: ${EM.length} au lieu de ${emLen}`);
        }

        return EM;
    }

    /**
     * Vérifie un encodage RSA-PSS à partir du haché et du message encodé.
     * Reconstitue le haché à partir du sel extrait et le compare.
     * @param {string} mHashHex - Le haché SHA-256 hexadécimal du message original.
     * @param {Buffer} EM - Le message encodé à vérifier.
     * @param {number} emBits - Nombre de bits effectifs du module RSA.
     * @returns {boolean} true si la vérification réussit, sinon une erreur est levée.
     */
    emsaPSSverify(mHashHex, EM, emBits) {
        const hLen = 32;
        const emLen = EM.length;

        if (emLen < hLen + 2)
            throw new Error("Encoded message too short");
        if (EM[emLen - 1] !== 0xbc)
            throw new Error("Invalid trailer byte");

        const mHash = Buffer.from(mHashHex, "hex");

        // Sépare les blocs : maskedDB et H
        const maskedDB = EM.slice(0, emLen - hLen - 1);
        const H = EM.slice(emLen - hLen - 1, emLen - 1);

        // Restaure DB = maskedDB ⊕ dbMask
        const dbMask = RSA.MGF1(H, maskedDB.length);
        const DB = Buffer.alloc(maskedDB.length);
        for (let i = 0; i < maskedDB.length; i++) {
            DB[i] = maskedDB[i] ^ dbMask[i];
        }

        // Applique les bits inutilisés à zéro
        const unusedBits = 8 * emLen - emBits;
        if (unusedBits > 0) {
            DB[0] &= 0xFF >> unusedBits;
        }

        // Recherche l'octet 0x01 après les 0x00
        let idx = -1;
        for (let i = 0; i < DB.length; i++) {
            if (DB[i] === 0x01) {
                idx = i;
                break;
            } else if (DB[i] !== 0x00) {
                throw new Error("Invalid DB format");
            }
        }
        if (idx < 0)
            throw new Error("0x01 byte not found in DB");

        // Extrait le sel
        const salt = DB.slice(idx + 1);
        if (salt.length !== hLen)
            throw new Error("Salt length incorrect");

        // Reconstitue M' = 0x00..00 || mHash || salt
        const M_ = Buffer.concat([Buffer.alloc(8, 0), mHash, salt]);
        const Hprime = Buffer.from(Hash.sha256(M_.toString("latin1")), "hex");

        // Compare les deux hachés
        if (!H.equals(Hprime))
            throw new Error("Hash mismatch");

        return true;
    }

    /**
     * Signe un message en utilisant RSA-PSS avec la clé privée donnée.
     * L'encodage PSS est appliqué avant l'opération RSA.
     * @param {string} message - Le message brut à signer.
     * @param {object} privateKey - La clé privée RSA {n, d}.
     * @returns {bigint} La signature numérique sous forme de grand entier.
     */
    signPSS(message, privateKey) {

        privateKey = RSA.decodeKeyBase64(privateKey);

        const emBits = privateKey.n.toString(2).length - 1;
        const emLen = Math.ceil(emBits / 8);

        const mHashHex = Hash.sha256(message);

        let EM = this.emsaPSSencode(mHashHex, emLen, emBits);

        // Padding si l'encodage est trop court
        if (EM.length !== emLen) {
            if (EM.length < emLen) {
                const pad = Buffer.alloc(emLen - EM.length, 0);
                EM = Buffer.concat([pad, EM]);
            } else {
                throw new Error(`Encoded message too long: EM.length=${EM.length}, emLen=${emLen}`);
            }
        }

        const m = BigInt("0x" + EM.toString("hex"));

        if (m >= privateKey.n) {
            throw new Error("Message trop grand pour RSA");
        }

        // Signature RSA
        const signature = RSA.modPow(m, privateKey.d, privateKey.n);
        return signature;
    }

    /**
     * Vérifie une signature RSA-PSS à partir du message et de la clé publique.
     * Déchiffre la signature et compare l'encodage avec le haché du message.
     * @param {bigint} signature - La signature numérique à vérifier.
     * @param {object} publicKey - La clé publique RSA {n, e}.
     * @param {string} message - Le message original signé.
     * @returns {boolean} true si la signature est valide, false sinon.
     */
    verifyPSS(signature, publicKey, message) {

        publicKey = RSA.decodeKeyBase64(publicKey);

        const emBits = publicKey.n.toString(2).length - 1;
        const k = Math.ceil(emBits / 8);

        const m = RSA.modPow(signature, publicKey.e, publicKey.n);

        let mHex = m.toString(16);
        if (mHex.length % 2)
            mHex = "0" + mHex;
        let mBuf = Buffer.from(mHex, "hex");

        if (mBuf.length > k) {
            throw new Error("Encoded message length too long in verification");
        }

        // Ajoute le padding à gauche si nécessaire
        const EMbuf = Buffer.alloc(k, 0);
        mBuf.copy(EMbuf, k - mBuf.length);

        const mHashHex = Hash.sha256(message);

        try {
            const result = this.emsaPSSverify(mHashHex, EMbuf, emBits);
            return result;
        } catch (e) {
            return false;
        }
    }

    // --- Fonctions générales

    /**
     * Teste si un nombre est premier avec le test de Miller-Rabin.
     * @param {bigint} n - Nombre à tester.
     * @param {number} [k=16] - Nombre d’itérations (plus grand = plus fiable).
     * @returns {boolean} Vrai si n est probablement premier, faux sinon.
     */
    static isPrimeMillerRabin(n, k = 16) {
        if (n === 2n || n === 3n)
            return true;
        if (n < 2n || n % 2n === 0n)
            return false;

        let r = 0n;
        let d = n - 1n;
        while (d % 2n === 0n) {
            d /= 2n;
            r++;
        }

        const bases = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n];
        for (let i = 0; i < k; i++) {
            const a = bases[i % bases.length];
            if (a >= n - 2n)
                continue;
            let x = RSA.modPow(a, d, n);
            if (x === 1n || x === n - 1n)
                continue;

            let continueOuter = false;
            for (let j = 0n; j < r - 1n; j++) {
                x = RSA.modPow(x, 2n, n);
                if (x === n - 1n) {
                    continueOuter = true;
                    break;
                }
            }
            if (continueOuter)
                continue;

            return false;
        }
        return true;
    }

    /**
     * Calcule (base^exp) mod modulo de manière efficace.
     * @param {bigint} base - La base.
     * @param {bigint} exp - L’exposant.
     * @param {bigint} mod - Le modulo.
     * @returns {bigint} Le résultat de la puissance modulaire.
     */
    static modPow(base, exp, mod) {
        let result = 1n;
        base = base % mod;
        while (exp > 0n) {
            if (exp % 2n === 1n)
                result = (result * base) % mod;
            base = (base * base) % mod;
            exp /= 2n;
        }
        return result;
    }

    /**
     * Calcule le plus grand commun diviseur (PGCD) de deux entiers.
     * @param {bigint} a
     * @param {bigint} b
     * @returns {bigint} Le PGCD de a et b.
     */
    static gcd(a, b) {
        while (b !== 0n) {
            [a, b] = [b, a % b];
        }
        return a;
    }

    /**
     * Calcule l’inverse modulo de a modulo m (a^(-1) mod m).
     * Utilise l’algorithme d’Euclide étendu.
     * @param {bigint} a
     * @param {bigint} m
     * @returns {bigint} L’inverse modulo de a.
     */
    static modInverse(a, m) {
        let m0 = m,
        t,
        q;
        let x0 = 0n,
        x1 = 1n;
        if (m === 1n)
            return 0n;
        while (a > 1n) {
            q = a / m;
            t = m;
            m = a % m;
            a = t;
            t = x0;
            x0 = x1 - q * x0;
            x1 = t;
        }
        if (x1 < 0n)
            x1 += m0;
        return x1;
    }

    /**
     * Parse une chaîne en BigInt selon le format donné.
     * @param {string} str - Chaîne représentant le nombre.
     * @param {string} [format="dec"] - Format ("dec", "hex", "b64").
     * @returns {bigint} Le BigInt résultant.
     * @throws {Error} Si le format est inconnu.
     */
    static parse(str, format = "dec") {
        if (format === "dec") {
            return BigInt(str);
        } else if (format === "hex") {
            if (str.startsWith("0x") || str.startsWith("0X")) {
                str = str.slice(2);
            }
            return BigInt("0x" + str);
        } else if (format === "b64") {
            const buffer = Buffer.from(str, "base64");
            let hex = "";
            for (const byte of buffer) {
                hex += byte.toString(16).padStart(2, "0");
            }
            return BigInt("0x" + hex);
        } else {
            throw new Error(`Format inconnu pour parse: ${format}`);
        }
    }

    /**
     * Formate un BigInt en chaîne selon le format donné.
     * @param {bigint} value - Le nombre à formater.
     * @param {string} [format="dec"] - Format cible ("dec", "hex", "b64").
     * @returns {string} La chaîne formatée.
     * @throws {Error} Si le format est inconnu.
     */
    static formatBigInt(value, format = "dec") {
        if (format === "dec") {
            return value.toString(10);
        } else if (format === "hex") {
            return "0x" + value.toString(16);
        } else if (format === "b64") {
            let hex = value.toString(16);
            if (hex.length % 2)
                hex = "0" + hex;
            return Buffer.from(hex, "hex").toString("base64");
        } else {
            throw new Error(`Format inconnu: ${format}`);
        }
    }

    /**
     * Calcule la racine entière k-ième d’un nombre n.
     * @param {bigint} n - Le nombre dont on cherche la racine.
     * @param {bigint} k - L’ordre de la racine (exposant).
     * @returns {bigint} La racine entière la plus grande telle que result^k ≤ n.
     * @throws {Error} Si n < 0 ou k ≤ 0.
     */
    static integerRoot(n, k) {
        if (n < 0n)
            throw new Error("Negative input not supported");
        if (n === 0n)
            return 0n;
        if (k <= 0n)
            throw new Error("Root exponent must be > 0");

        let low = 1n,
        high = n,
        mid;

        while (low < high) {
            mid = (low + high + 1n) >> 1n;
            const midPow = RSA.pow(mid, k);
            if (midPow <= n) {
                low = mid;
            } else {
                high = mid - 1n;
            }
        }
        return low;
    }

    /**
     * Calcule base^exp (exposant entier) sans modulo.
     * @param {bigint} base
     * @param {bigint} exp
     * @returns {bigint} base^exp
     */
    static pow(base, exp) {
        let result = 1n;
        while (exp > 0n) {
            if (exp % 2n === 1n)
                result *= base;
            base *= base;
            exp >>= 1n;
        }
        return result;
    }

    /**
     * Décode une clé RSA sérialisée et encodée en Base64.
     * Convertit les chaînes "123n" en BigInt.
     * @param {string} base64Key - La clé RSA en Base64, sérialisée avec stringifyWithBigInt.
     * @returns {object|null} L'objet clé avec ses composants BigInt, ou null en cas d'erreur.
     */
    static decodeKeyBase64(base64Key) {
        try {

            const decodedJson = Buffer.from(base64Key, 'base64').toString('utf8');

            const keyObj = JSON.parse(decodedJson, (key, value) => {
                if (typeof value === 'string' && /^\d+n$/.test(value)) {
                    return BigInt(value.slice(0, -1));
                }
                return value;
            });

            return keyObj;

        } catch (error) {
            console.error("Erreur de décodage de la clé :", error);
            return null;
        }
    }

    /**
     * Sérialise un objet JSON contenant des BigInt en les convertissant en chaînes avec suffixe 'n' (ex: 123n → "123n").
     * Utile pour un encodage compatible avec JSON.stringify et une future désérialisation.
     * @param {any} obj - L'objet contenant éventuellement des BigInt.
     * @returns {string} La chaîne JSON sérialisée avec les BigInt encodés.
     */
    static stringifyWithBigInt(obj) {
        return JSON.stringify(obj, (key, value) =>
            typeof value === 'bigint' ? value.toString() + 'n' : value);
    }

    /**
     * Analyse une chaîne JSON contenant des BigInt sérialisés (ex: "123n") et les reconvertit en BigInt.
     * Accepte également les entiers classiques sous forme de chaînes (ex: "123").
     * @param {string} jsonStr - La chaîne JSON à parser.
     * @returns {any} L'objet JSON avec les BigInt restaurés.
     */
    static parseWithBigInt(jsonStr) {
        return JSON.parse(jsonStr, (key, value) => {
            if (typeof value === 'string') {
                if (/^\d+n$/.test(value))
                    return BigInt(value.slice(0, -1));
                if (/^\d+$/.test(value))
                    return BigInt(value);
            }
            return value;
        });
    }

}

/**
 * Classe pour générer des nombres aléatoires cryptographiquement sécurisés
 * en utilisant l’algorithme Blum Blum Shub (BBS).
 */
class GenerateCryptoRandomNumber {

    /**
     * Initialise la classe avec un facteur qui définit la taille relative
     * des nombres premiers p et q utilisés dans BBS (généralement 2).
     * @param {number} prop_bbs_factor - Facteur de proportion des bits pour p et q.
     */
    constructor(prop_bbs_factor = 2) {
        this.prop_bbs_factor = prop_bbs_factor;
    }

    /**
     * Initialise le générateur pseudo-aléatoire BBS avec des nombres premiers p et q.
     * @param {number} bits - La taille en bits du nombre aléatoire à générer.
     */
    initPRNG(bits) {
        this.bits = bits;

        // Génération de p ≡ 3 mod 4
        this.seed = BigInt("0x" + generateSecureSeedNode(59));
        const p = BlumBlumShub.generatePrimes3Mod4(this.seed, this.bits / this.prop_bbs_factor);

        // Génération de q ≡ 3 mod 4
        this.seed = BigInt("0x" + generateSecureSeedNode(47));
        const q = BlumBlumShub.generatePrimes3Mod4(this.seed, this.bits / this.prop_bbs_factor);

        // Nouvelle graine pour BBS
        this.seed = BigInt("0x" + generateSecureSeedNode(31));
        this.prng = new BlumBlumShub(this.seed, p, q, this.bits);
    }

    /**
     * Génère et retourne un nombre aléatoire de `this.bits` bits.
     * @returns {BigInt} - Un entier aléatoire (pas forcément premier).
     */
    nextNumber() {
        return this.prng.nextBits(this.bits);
    }
}

// ----------------------------------------------------------------
// ----------------------------------------------------------------
// ---------------------------------------------------------------- Exemple d'utilisation génération de clés
/*
console.log("Générations de la paire de clés en cours...");
const rsa = new RSA();
const {
    publicKey,
    privateKey
} = rsa.generateKeys(2 ** 10); // p et q = 2^10 => module de 2^11

// Affichage des clés en base64 (clé publique et clé privée)
console.log("\nClé publique (base64) :", publicKey);
console.log("\nClé privée  (base64) :", privateKey);
*/

// ----------------------------------------------------------------
// ----------------------------------------------------------------
// ---------------------------------------------------------------- Exemple d'utilisation chiffrement/déchiffrement RSA + OAEP + Blinding + CRT

// Génération des clés RSA
console.log("Générations de la paire de clés en cours...");
const rsa = new RSA();
const {
publicKey,
privateKey
} = rsa.generateKeys(2 ** 10); // p et q = 2^10 => module de 2^11

// Affichage des clés en base64 (clé publique et clé privée)
console.log("\nClé publique (base64) :", publicKey);
console.log("\nClé privée  (base64) :", privateKey);

// Message à chiffrer
const message = "Message à chiffrer";
console.log("\nMessage original :", message);

// Chiffrement du message (OAEP) avec la clé publique (e, n)
const encrypted = rsa.encryptOAEP(message, publicKey);
console.log("\nMessage chiffré (hex) :", encrypted.toString(16));

// Déchiffrement du message (OAEP + BLinding + CRT) avec la clé privée (d, n)
const decrypted = rsa.decryptOAEPBlindingCRT(encrypted, privateKey);
console.log("\nMessage déchiffré :", decrypted);


// ----------------------------------------------------------------
// ----------------------------------------------------------------
// ---------------------------------------------------------------- Exemple d'utilisation signature/vérification RSA-PSS

/*
// Génération des clés RSA
console.log("Générations de la paire de clés en cours...");
const rsa = new RSA();
const { publicKey, privateKey } = rsa.generateKeys(2 ** 10); // p et q = 2^10 => module de 2^11

// Signature
const message = "Ceci est un message à signer";
const signature = rsa.signPSS(message, privateKey);
console.log("Signature (hex) :", signature.toString(16));

// Vérification
const valid = rsa.verifyPSS(signature, publicKey, message);
console.log(valid ? "Signature valide" : "Signature invalide");
*/
