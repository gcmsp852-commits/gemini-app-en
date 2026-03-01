/**
 * ZXing QR Twin Extension (zxing-twin-patch.js)
 * ZXingのプロトタイプを動的に拡張し、QRツインのXOR復号と管理部解析を可能にします。
 */
(function(window) {
    if (typeof ZXing === 'undefined' || !ZXing.qrcode || !ZXing.qrcode.Decoder) {
        console.error("ZXing library must be loaded before zxing-twin-patch.js");
        return;
    }

    // --- 1. デコーダーのインターセプト（QR1とQR2の分岐処理） ---
    const originalDecode = ZXing.qrcode.Decoder.prototype.decode;
    ZXing.qrcode.Decoder.prototype.decode = function(bits, hints) {
        try {
            // まず通常のデコードを試行（暗号化されていない第1QRコード用）
            const result = originalDecode.call(this, bits, hints);
            result.isTwinEncrypted = false; // 識別フラグ
            return result;
        } catch (error) {
            // 通常デコード失敗時、パスワードマスクが存在すればXOR復号を試行（第2QRコード用）
            if (window.twinDecryptMask) {
                window.__applyTwinXor = true; // BitMatrixParserにXOR適用を指示
                try {
                    const result = originalDecode.call(this, bits, hints);
                    result.isTwinEncrypted = true; // 識別フラグ
                    return result;
                } catch (err2) {
                    throw err2;
                } finally {
                    window.__applyTwinXor = false;
                }
            }
            throw error;
        }
    };

    // --- 2. コード語（生データ）抽出時のXORインジェクション ---
    const originalReadCodewords = ZXing.qrcode.BitMatrixParser.prototype.readCodewords;
    ZXing.qrcode.BitMatrixParser.prototype.readCodewords = function() {
        const codewords = originalReadCodewords.call(this);
        // デコーダーからの指示があれば、XORマスクをコード語に適用
        if (window.__applyTwinXor && window.twinDecryptMask) {
            for (let i = 0; i < codewords.length; i++) {
                codewords[i] ^= window.twinDecryptMask[i % window.twinDecryptMask.length];
            }
        }
        return codewords;
    };

    // --- 3. QRツイン専用の暗号・解析ユーティリティ ---
    window.TwinCrypto = {
        sha256Bytes: async function(msgBytes) {
            const hashBuffer = await crypto.subtle.digest('SHA-256', msgBytes);
            return new Uint8Array(hashBuffer);
        },
        // 要件④：パスワードからのアプリパターンマスク生成（SHA-256の連鎖）
        deriveMask: async function(password, neededBytes) {
            const out = new Uint8Array(neededBytes);
            let filled = 0;
            const pwBytes = new TextEncoder().encode(password);
            let h = await this.sha256Bytes(pwBytes);
            
            while (filled < neededBytes) {
                const take = Math.min(32, neededBytes - filled);
                out.set(h.subarray(0, take), filled);
                filled += take;
                if (filled >= neededBytes) break;
                h = await this.sha256Bytes(h); 
            }
            return out;
        },
        // 要件②：管理部の識別（生バイト列から16bit管理部を抽出）
        getMgmtBits: function(rawBytes, decodedText) {
            try {
                const textLength = new TextEncoder().encode(decodedText).length;
                let bitOffset = 0;
                const readBits = (n) => {
                    let val = 0;
                    for(let i=0; i<n; i++) {
                        const byteIdx = Math.floor(bitOffset / 8);
                        if(byteIdx >= rawBytes.length) return null;
                        val = (val << 1) | ((rawBytes[byteIdx] >> (7 - (bitOffset % 8))) & 1);
                        bitOffset++;
                    }
                    return val;
                };
                
                const mode = readBits(4);
                if (mode !== 4) return null; // Byteモード以外は除外
                
                let len = readBits(8);
                if (len !== textLength) {
                    bitOffset = 4;
                    len = readBits(16);
                    if (len !== textLength) return null;
                }
                
                bitOffset += len * 8; // データ部をスキップ
                const remaining = (rawBytes.length * 8) - bitOffset;
                const termLen = Math.min(4, remaining);
                readBits(termLen); // 終端子をスキップ
                
                if ((rawBytes.length * 8) - bitOffset >= 16) {
                    return readBits(16);
                }
                return null;
            } catch(e) { return null; }
        },
        // 管理部の「アプリ暗号化ビット(左から8番目)」を判定
        isAppEncrypted: function(mgmtBits) {
            if (mgmtBits === null) return false;
            return ((mgmtBits >> 8) & 1) === 1; 
        }
    };
})(window);