
import { Scalar, Point, Curve } from '@futuretense/curve-interface';
import { encrypt, decrypt } from '@futuretense/secret-box';
import { sha256, sha512 } from './hash';

export type ReKey = {
    R1: Buffer;                 //  Point
    R2: Buffer;                 //  Point
    R3: Buffer;
}

export type EncryptedMessage = {
    tag: Buffer;
    encryptedKey: Buffer;       //  Point
    messageChecksum: Buffer;
    overallChecksum: Buffer;
    data: Buffer;
}

export type ReEncryptedMessage = {
    D1: Buffer;                 //  Point
    D2: Buffer;
    D3: Buffer;
    D4: Buffer;                 //  Point
    D5: Buffer;                 //  Point
}

/**
 * @public
 */

export class MessageChecksumFailure extends Error {}

/**
 * @public
 */

export class OverallChecksumFailure extends Error {}

/**
 * @public
 */
export class PRE {

    /**
     * @internal
     */
    curve: Curve;

    /**
     * @internal
     */
    x: Scalar;   //  private key

    /**
     * @internal
     */
    P: Point;   //  public key

    constructor(
        privateKey: Buffer,
        curve: Curve
    ) {
        this.curve = curve;
        this.x = this.curve.scalarFromBuffer(privateKey);
        this.P = this.curve.basepoint.mul(this.x);
    }

    async selfEncrypt(msg: Buffer, tag: Buffer): Promise<EncryptedMessage> {

        const t = this.curve.randomScalar();
        const T = this.curve.basepoint.mul(t);

        //  hash1
        const h  = this.curve.scalarFromBuffer(sha256(tag, this.x.toBuffer()));
        const hG = this.curve.basepoint.mul(h);

        const encryptedKey = T.add(hG).toBuffer();
        const Tbuf = T.toBuffer();

        //  encrypt msg using key
        const key = sha512(Tbuf);
        const data = await encryptSymmetric(msg, key);

        const messageChecksum = sha512(msg, Tbuf);
        const alp = this.curve.scalarFromHash(
            tag,
            this.x.toBuffer()
        ).toBuffer();

        const overallChecksum = sha512(
            encryptedKey,
            data,
            messageChecksum,
            alp
        );

        return {
            tag,
            encryptedKey,
            data,
            messageChecksum,
            overallChecksum
        }
    }

    async selfDecrypt(msg: EncryptedMessage): Promise<Buffer> {

        const xb = this.x.toBuffer();
        const alp = this.curve.scalarFromHash(msg.tag, xb);
        const check1 = sha512(
            msg.encryptedKey,
            msg.data,
            msg.messageChecksum,
            alp.toBuffer()
        );

        if (!check1.equals(msg.overallChecksum)) {
            throw new OverallChecksumFailure();
        }

        //  hash1
        const h = this.curve.scalarFromBuffer(sha256(msg.tag, xb));
        const hG = this.curve.basepoint.mul(h);

        const encryptedKey = this.curve.pointFromBuffer(msg.encryptedKey);
        const Tbuf = encryptedKey.sub(hG).toBuffer();
        const key = sha512(Tbuf);
        const data = await decryptSymmetric(msg.data, key);

        //  hash3
        const check2 = sha512(data, Tbuf);
        if (!check2.equals(msg.messageChecksum)) {
            throw new MessageChecksumFailure();
        }

        return data;
    }

    async reDecrypt(
        d: ReEncryptedMessage,
    ): Promise<Buffer> {

        const D1 = this.curve.pointFromBuffer(d.D1);
        const D4 = this.curve.pointFromBuffer(d.D4);
        const D5 = this.curve.pointFromBuffer(d.D5);
        const txG = D5.mul(this.x);                                             //  x * D5 = x * tG

        const bInv = this.curve.scalarFromHash(
            txG.toBuffer(),
            d.D2,
            d.D3,
            d.D4,
            d.D5
        ).inverse();

        const xInv = this.x.inverse();

        const T1 = D1.mul(bInv);
        const T2 = D4.mul(xInv);
        const Tbuf = T1.sub(T2).toBuffer();
        const key = sha512(Tbuf);
        const data = await decryptSymmetric(d.D2, key);

        //  hash3
        const check2 = sha512(data, Tbuf);
        if (!check2.equals(d.D3)) {
            throw '181!';
        }

        return data;
    }

    generateReKey(publicKey: Buffer, tag: Buffer): ReKey {

        const P = this.curve.pointFromBuffer(publicKey);
        const xb = this.x.toBuffer();
        const r = this.curve.randomScalar();
        const h = this.curve.scalarFromBuffer(sha256(tag, xb));

        const res: Partial<ReKey> = {};
        res.R1 = this.curve.basepoint.mul(r.sub(h)).toBuffer();                 //  rG - hG
        res.R2 = P.mul(r).toBuffer();                                           //  rP = rxG
        res.R3 = this.curve.scalarFromHash(tag, xb).toBuffer();
        return res as ReKey;
    }
}

export namespace PRE {

    export function reEncrypt(
        publicKey: Buffer,
        msg: EncryptedMessage,
        rekey: ReKey,
        curve: Curve
    ): ReEncryptedMessage {

        const check1 = sha512(
            msg.encryptedKey,
            msg.data,
            msg.messageChecksum,
            rekey.R3
        );

        if (!check1.equals(msg.overallChecksum)) {
            throw new OverallChecksumFailure();
        }

        const P = curve.pointFromBuffer(publicKey);
        const t = curve.randomScalar();
        const txG = P.mul(t);                                                   //  tP = txG

        const res: Partial<ReEncryptedMessage> = {};
        res.D2 = msg.data;
        res.D3 = msg.messageChecksum;
        res.D4 = rekey.R2;
        res.D5 = curve.basepoint.mul(t).toBuffer()                              //  tG

        //  hash7
        const bet = curve.scalarFromHash(
            txG.toBuffer(),
            res.D2,
            res.D3,
            res.D4,
            res.D5
        );

        const R1 = curve.pointFromBuffer(rekey.R1);
        const encryptedKey = curve.pointFromBuffer(msg.encryptedKey).add(R1);
        res.D1 = encryptedKey.mul(bet).toBuffer();

        return res as ReEncryptedMessage;
    }
}

//----------------------------------------------------------------------------//

/**
 * @internal
 * @param data -
 * @param keyHash -
 */
async function encryptSymmetric(data: Buffer, keyHash: Buffer): Promise<Buffer> {
    const key = keyHash.slice(0, 32);
    const nonce = keyHash.slice(32, 32 + 12);
    return Buffer.from(await encrypt(data, key, nonce, true));
}

/**
 * @internal
 * @param data -
 * @param keyHash -
 */
async function decryptSymmetric(data: Buffer, keyHash: Buffer): Promise<Buffer> {
    const key = keyHash.slice(0, 32);
    const nonce = keyHash.slice(32, 32 + 12);
    return Buffer.from(await decrypt(data, key, nonce, true));
}
