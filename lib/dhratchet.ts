/**
 * d4dr - d4's double ratchet because they are bored.
 * Specification by Open Whisper Systems <https://signal.org/docs/specifications/doubleratchet/>
 * Powered by Libsodium <https://libsodium.gitbook.io/doc/>
 *
 * Implemented by d4 <https://1dotd4.github.io>
 *
 * rnbqkbnr/pppppppp/8/8/3P4/8/PPP1PPPP/RNBQKBNR b KQkq - 0 1
 *
 */
import {
    CryptographyKey,
    Ed25519PublicKey,
    Ed25519SecretKey,
    SodiumPlus,
    X25519PublicKey,
    X25519SecretKey
} from "sodium-plus";
import { IdentityKeyPair
       , IdentityKeyManagerInterface
       , SessionKeyManagerInterface
       } from "./persistence";
import { Keypair, wipe } from "./util";
import { promises as fsp } from 'fs';
import * as path from 'path';
import * as os from 'os';

export type DHKeyPair = {preKeySecret: X25519SecretKey, preKeyPublic: X25519PublicKey};
type SessionKeys = {sending: CryptographyKey, receiving: CryptographyKey};

/* 
export interface SessionKeyManagerInterface {
    getAssocData(id: string):
        Promise<string>;
    getEncryptionKey(id: string, recipient?: boolean):
        Promise<CryptographyKey>;
    destroySessionKey(id: string):
        Promise<void>;
    listSessionIds():
        Promise<string[]>;
    setAssocData(id: string, assocData: string):
        Promise<void>;
    setSessionKey(id: string, key: CryptographyKey, recipient?: boolean):
        Promise<void>;
}
*/

/** note I'm not implementing the MKSKIPPED
 */
type Ratchet = { rootKey: CryptographyKey
               , pairSending: DHKeyPair
               , pairReceiving: DHKeyPair
               , chainKeySending: CryptographyKey
               , nSent: number
               , nReceived: number
               };

class DoubleRatchetSessionKeyManager {
  sodium: SodiumPlus;
  assocData: Map<string, string>;
  sessions: Map<string, Ratchet>;


  constructor(sodium?: SodiumPlus) {
    if (sodium) {
      this.sodium = sodium;
    } else {
      this.getSodium().then(() => {});
    }
    this.sessions = new Map<string, Ratchet>();
    this.assocData = new Map<string, string>();
  }

  /**
   * @returns {SodiumPlus}
   */
  async getSodium(): Promise<SodiumPlus> {
      if (!this.sodium) {
          this.sodium = await SodiumPlus.auto();
      }
      return this.sodium;
  }

  async getAssocData(id: string): Promise<string> {
    return this.assocData[id];
  }

  async setAssocData(id: string, assocData: string): Promise<void> {
    this.assocData[id] = assocData;
  }

  async listSessionIds(): Promise<string[]> {
    return Object.keys(this.sessions);
  }

  async setSessionKey(id: string, key: CryptographyKey, recipient?: boolean): Promise<void> {
    this.sessions[id].rootKey = key;
  }

  async getEncryptionKey(id: string): Promise<CryptographyKey> {
    if (!this.sessions[id]) {
        throw new Error('Key does not exist for client: ' + id);
    }

    const fullhash = await this.sodium.crypto_generichash(
        'A FUCKING RAT',
        new CryptographyKey(new Buffer('aa')),
        64
    );
        /*
        if (recipient) {
            const keys = await this.symmetricRatchet(this.sessions[id].receiving);
            this.sessions[id].receiving = keys[0];
            return keys[1];
        }
            */
    return (new CryptographyKey(fullhash.slice(0,  32)));
  }

  /*
  async getEncryptionKey(id: string, plaintext: string,) {
    if (!this.sessions[id]) {
        throw new Error('Key does not exist for client: ' + id);
    }
  }
  */
}



/**
 * This is a very basic example class for a session key manager.
 *
 * If you do not specify one, the X3DH library will use this.
 *
export class DoubleRatchetSessionKeyManager implements SessionKeyManagerInterface {
    assocData: Map<string, string>;
    sodium: SodiumPlus;
    sessions: Map<string, SessionKeys>;

    newSessions: Map<string, Ratchet>;

    constructor(sodium?: SodiumPlus) {
        if (sodium) {
            this.sodium = sodium;
        } else {
            // Just do this up-front.
            this.getSodium().then(() => {});
        }
        this.sessions = new Map<string, SessionKeys>();
        this.assocData = new Map<string, string>();
    }

    /**
     * @returns {SodiumPlus}
     *
    async getSodium(): Promise<SodiumPlus> {
        if (!this.sodium) {
            this.sodium = await SodiumPlus.auto();
        }
        return this.sodium;
    }

    async getAssocData(id: string): Promise<string> {
        return this.assocData[id];
    }

    async listSessionIds(): Promise<string[]> {
        const ids = [];
        for (let i in this.sessions) {
            ids.push(i);
        }
        return ids;
    }

    async setAssocData(id: string, assocData: string): Promise<void> {
        this.assocData[id] = assocData;
    }

    /**
     * Override the session key for a given participation partner.
     *
     * Note that the actual sending/receiving keys will be derived from a BLAKE2b
     * hash with domain separation (sending vs receiving) to ensure that messages
     * sent/received are encrypted under different keys.
     *
     * @param {string} id           Participant ID.
     * @param {CryptographyKey} key Incoming key.
     * @param {boolean} recipient   Are we the recipient? (Default: No.)
     *
    async setSessionKey(id: string, key: CryptographyKey, recipient?: boolean): Promise<void> {
        const sodium = await this.getSodium();
        this.sessions[id] = {};
        if (recipient) {
            this.sessions[id].receiving = new CryptographyKey(
                await sodium.crypto_generichash('sending', key)
            );
            this.sessions[id].sending = new CryptographyKey(
                await sodium.crypto_generichash('receiving', key)
            );
        } else {
            this.sessions[id].receiving = new CryptographyKey(
                await sodium.crypto_generichash('receiving', key)
            );
            this.sessions[id].sending = new CryptographyKey(
                await sodium.crypto_generichash('sending', key)
            );
        }
    }

    /**
     * Get the encryption key for a given message.
     *
     * !!!! IMPORTANT !!!!
     * This is a very rough proof-of-concept that doesn't
     * support out-of-order messages.
     *
     * Instead, it derives a 512-bit hash from the current key, then
     * updates the session key with the leftmost 256 bits of that hash,
     * and returns the rightmost 256 bits as the encryption key.
     *
     * You should design your session key management protocol more
     * appropriately for your use case.
     *
     * @param {string} id
     * @param {boolean} recipient
     * @returns {CryptographyKey}
     *
    async getEncryptionKey(id: string, recipient?: boolean): Promise<CryptographyKey> {
        if (!this.sessions[id]) {
            throw new Error('Key does not exist for client: ' + id);
        }
        if (recipient) {
            const keys = await this.symmetricRatchet(this.sessions[id].receiving);
            this.sessions[id].receiving = keys[0];
            return keys[1];
        } else {
            const keys = await this.symmetricRatchet(this.sessions[id].sending);
            this.sessions[id].sending = keys[0];
            return keys[1];
        }
    }

    /**
     * This is a very basic symmetric ratchet based on
     * BLAKE2b-512.
     *
     * The first 256 bits of the output are stored as the
     * future ratcheting key.
     *
     * The remaining bits are returned as the encryption key.
     *
     * @param {CryptographyKey} inKey
     * @returns {CryptographyKey[]}
     *
    async symmetricRatchet(inKey: CryptographyKey): Promise<CryptographyKey[]> {
        const sodium = await this.getSodium();
        const fullhash = await sodium.crypto_generichash(
            'Symmetric Ratchet',
            inKey,
            64
        );
        return [
            new CryptographyKey(fullhash.slice(0,  32)),
            new CryptographyKey(fullhash.slice(32, 64)),
        ]
    }



    /**
     * Delete the session.
     *
     * @param {string} id
     *
    async destroySessionKey(id: string): Promise<void> {
        if (!this.sessions[id]) {
            return;
        }
        if (this.sessions[id].sending) {
            await wipe(this.sessions[id].sending);
        }
        if (this.sessions[id].receiving) {
            await wipe(this.sessions[id].receiving);
        }
        delete this.sessions[id];
    }
}
*/

