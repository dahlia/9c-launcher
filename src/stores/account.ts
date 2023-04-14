import {
  decipherV3,
  getAccountFromFile,
  listKeystoreFiles,
  rawPrivateKeyToV3,
  sanitizeKeypath,
  getDefaultKeystorePath,
  V3Keystore,
} from "@planetarium/account-local";
import { Address, RawPrivateKey } from "@planetarium/account";
import {
  KeyId,
  PassphraseEntry,
  Web3Account,
  Web3KeyStore,
  getDefaultWeb3KeyStorePath,
} from "@planetarium/account-web3-secret-storage";
import { createAccount } from "@planetarium/account-raw";
import { Account, deriveAddress } from "@planetarium/sign";
// FIXME these imports cause matter since file-system related features aren't
// possible on some targets (e.g., browser). thus we should extract them from
// this store to the dedicated backend, and inject that into this.
import fs from "fs";
import path from "path";
import { action, observable, makeObservable } from "mobx";
import { utils } from "@noble/secp256k1";
import { app } from "@electron/remote";

interface ILoginSession {
  account: Account;
  publicKey: string;
  address: string;
  privateKey: string;
}

export async function getKeyStorePath(): Promise<string> {
  const keyStorePath = getDefaultWeb3KeyStorePath();

  if (process.platform === "darwin") {
    // macOS: Migrate the keystore from the legacy path to the new path.
    //   legacy path: $HOME/Library/Application Support/planetarium/keystore
    //   new path:    $XDG_DATA_HOME/planetarium/keystore
    const legacyPath = path.join(
      app.getPath("appData"),
      "planetarium",
      "keystore"
    );

    // If the legacy keystore directory exists but is already migrated,
    // just use the new keystore directory:
    try {
      await fs.promises.stat(path.join(legacyPath, "__MIGRATED__"));
      return keyStorePath;
    } catch (e) {
      if (typeof e !== "object" || e.code !== "ENOENT") throw e;
    }

    let dir: fs.Dir;
    try {
      dir = await fs.promises.opendir(legacyPath);
    } catch (e) {
      if (typeof e === "object" && e.code === "ENOENT") {
        return keyStorePath;
      }

      throw e;
    }

    const pattern =
      /^(?:UTC--([0-9]{4}-[0-9]{2}-[0-9]{2})T([0-9]{2}-[0-9]{2}-[0-9]{2})Z--)?([0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12})(?:.json)?$/i;
    for await (const dirEntry of dir) {
      if (!dirEntry.isFile()) continue;
      const match = pattern.exec(dirEntry.name);
      if (match === null) continue;
      await fs.promises.copyFile(
        path.join(legacyPath, dirEntry.name),
        path.join(keyStorePath, dirEntry.name)
      );
    }

    // Mark the keystore as migrated:
    await fs.promises.writeFile(
      path.join(legacyPath, "__MIGRATED__"),
      `All key files in this directory are migrated to the new path.
This file is used to prevent the keystore from being migrated again.
See also: ${keyStorePath}
Migrated at: ${new Date().toISOString()}\n`
    );
  }

  return keyStorePath;
}

export default class AccountStore {
  private _privateKeyToRecovery: RawPrivateKey | null = null;

  async getKeyStore(passphrase: string | undefined): Promise<Web3KeyStore> {
    const passphraseEntry: PassphraseEntry = {
      authenticate(keyId: string, firstAttempt: boolean): Promise<string> {
        if (passphrase === undefined) throw new Error("No passphrase given.");
        if (firstAttempt) return Promise.resolve(passphrase);
        throw new Error("Incorrect passphrase.");
      },
      configurePassphrase(): Promise<string> {
        if (passphrase === undefined) throw new Error("No passphrase given.");
        return Promise.resolve(passphrase);
      },
    };
    return new Web3KeyStore({ passphraseEntry, path: await getKeyStorePath() });
  }

  @observable
  public isLogin: boolean = false;

  @observable
  public activationKey: string = "";

  @observable
  public loginSession: ILoginSession | null = null;

  constructor() {
    makeObservable(this);
    this.setKeys(this.listKeyFiles());
  }

  @action
  login = async (account: Account, password: string) => {
    const bs = await account.getPublicKey(false);
    const address = await deriveAddress(account);

    this.loginSession = {
      account,
      publicKey: utils.bytesToHex(bs),
      address,
      privateKey: (
        await this.loadPrivateKeyFromAddress(address, password)
      ).toString("hex"),
    };
  };

  @action
  getAccount = async (
    address: string | Address,
    passphrase: string
  ): Promise<RawPrivateKey> => {
    const account = await this.findKeyByAddress(address);
    return accoun;
  };

  @action
  removeKeyByAddress = (address: Address) => {
    this.keyring.forEach((key) => {
      if (
        key.address.replace("0x", "").toLowerCase() ===
        address.replace("0x", "").toLowerCase()
      ) {
        this.removeKey(key);
      }
    });
  };

  @action
  setKeys = (keys: ProtectedPrivateKey[]) => {
    this.keyring.replace(keys);
  };

  @action
  setLoginStatus = (status: boolean) => {
    this.isLogin = status;
  };

  @action
  setActivationKey = (activationKey: string) => {
    this.activationKey = activationKey;
  };

  @action
  listKeyFiles = (): ProtectedPrivateKey[] => {
    try {
      return listKeystoreFiles().map((keyId: string) => {
        const key: V3Keystore = JSON.parse(
          fs.readFileSync(path.resolve(sanitizeKeypath(), keyId), "utf8")
        );
        const ppk: ProtectedPrivateKey = {
          keyId: key.id,
          address: key.address,
          path: path.resolve(sanitizeKeypath(), keyId),
        };
        return ppk;
      });
    } catch (e) {
      console.error(e);
      return [];
    }
  };

  @action
  findKeyByAddress = async (
    address: string | Address
  ): Promise<{ keyId: KeyId; account: Web3Account } | undefined> => {
    if (typeof address === "string") {
      try {
        address = Address.fromHex(address, true);
      } catch (e) {
        // Invalid address
        return undefined;
      }
    }
    const keyStore = await this.getKeyStore(undefined);
    for await (const entry of keyStore.list()) {
      const account = await keyStore.get(entry.keyId);
      if (account.result !== "success") continue;
      if (account.metadata.address.equals(address)) return account;
    }
    return undefined;
  };

  //TODO: This function solely depending on behavior that
  //addV3 push to end of the array, we need to fix that.
  @action
  importRaw = async (privateKeyHex: string, passphrase: string) => {
    const keyStore = await this.getKeyStore(passphrase);
    const privateKey = RawPrivateKey.fromHex(privateKeyHex);
    const result = await keyStore.import(privateKey);
    if (result.result === "error") {
      throw new Error(result.message);
    }
    return privateKey;
  };

  @action
  isValidPrivateKey = (privateKey: string): boolean => {
    try {
      createAccount(privateKey);
    } catch (e) {
      return false;
    }
    return true;
  };

  beginRecovery = (privateKey: RawPrivateKey) => {
    if (this._privateKeyToRecovery) {
      throw new Error("There is another recovery in progress.");
    }

    this._privateKeyToRecovery = privateKey;
  };

  completeRecovery = async (passphrase: string) => {
    if (!this._privateKeyToRecovery) {
      throw new Error("There is no recovery in progress.");
    }

    const account = await this.importRaw(
      this._privateKeyToRecovery.toString("hex"),
      passphrase
    );
    const address = await deriveAddress(account);
    if (this.keyring.length <= 0) {
      throw new Error("There's no key in keyring despite we just generated.");
    }

    const importedKey = this.popKey();
    this.removeKeyByAddress(address);
    this.addKey(importedKey!);

    // Wipe Buffer
    this._privateKeyToRecovery.fill(0);
    this._privateKeyToRecovery = null;
    return account;
  };
}
