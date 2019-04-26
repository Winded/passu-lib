import * as crypto from 'crypto';
import * as bcrypt from 'bcrypt';

const algorithm = 'aes-256-cbc';

function shuffleString(str: string): string {
    var a = str.split(''),
    n = a.length;

    for(var i = n - 1; i > 0; i--) {
        var j = Math.floor(Math.random() * (i + 1));
        var tmp = a[i];
        a[i] = a[j];
        a[j] = tmp;
    }
    return a.join('');
}

export interface PasswordPolicy {
    readonly length?: number;
    readonly useLowercase?: boolean;
    readonly useUppercase?: boolean;
    readonly useNumbers?: boolean;
    readonly useSpecial?: boolean;
}

interface PasswordEntry {
    readonly name: string;
    readonly password: string;
    readonly description: string;
    readonly policyOverride: PasswordPolicy;
}

interface PasswordData {
    passwordPolicy: PasswordPolicy;
    entries: Array<PasswordEntry>;
}

export class PasswordDatabase {
    /**
     * Decrypt and deserialize a password database from given data buffer.
     * @param bytes Data buffer to decrypt and deserialize
     * @param inputPassword Master password of the database, as inputted by user (not hashed)
     */
    static fromData(bytes: Buffer, inputPassword: string): PasswordDatabase {
        let bOffset = 0;

        let ivByteLength = bytes.readUInt8(bOffset);
        bOffset += 1;
        let iv = bytes.slice(bOffset, bOffset + ivByteLength);
        bOffset += ivByteLength;

        let passwordSalt = bytes.slice(bOffset, bOffset + 29).toString();
        bOffset += 29;

        let edataByteLength = bytes.readUInt32BE(bOffset);
        bOffset += 4;
        let edata = bytes.slice(bOffset, bOffset + edataByteLength);

        let passwordHash = bcrypt.hashSync(inputPassword, passwordSalt).substr(29);

        let decipher = crypto.createDecipheriv(algorithm, passwordHash + '0', iv);
        let sdata = Buffer.concat([decipher.update(edata), decipher.final()]).toString();

        let data = JSON.parse(sdata);

        let db = new PasswordDatabase(inputPassword);
        db.data = data;

        return db;
    }

    modified: boolean;
    private passwordHash: string;
    private passwordSalt: string;
    private data: PasswordData;

    constructor(inputPassword: string) {
        this.password = inputPassword;

        this.data = {
            passwordPolicy: {
                length: 32,
                useLowercase: true,
                useUppercase: true,
                useNumbers: true,
                useSpecial: true,
            },
            entries: [],
        };

        this.modified = false;
    }

    get defaultPolicy() {
        return this.data.passwordPolicy;
    }

    set defaultPolicy(value: PasswordPolicy) {
        if(value.length !== undefined && value.length <= 0) {
            throw new EvalError(`Password policy length can't be 0 or lower`);
        }
        
        this.data.passwordPolicy = { ...this.data.passwordPolicy, ...value };
        this.modified = true;
    }

    /**
     * Set a new password for the password database
     */
    set password(value: string) {
        this.passwordSalt = bcrypt.genSaltSync(10);
        this.passwordHash = bcrypt.hashSync(value, this.passwordSalt).substr(29);
    }

    /**
     * Generates a new password for the given password entry.
     * @param entryName Name of the entry to generate password for
     * @returns The updated password entry
     */
    generatePassword(entryName: string): PasswordEntry {
        let entry = this.getEntry(entryName);
        if (!entry) {
            throw new Error(`Entry ${name} not found.`);
        }

        let policy = { ...this.data.passwordPolicy, ...entry.policyOverride };

        let sets: Array<string> = [];
        if (policy.useLowercase) {
            sets.push('abcdefghijklmnopqrstuvwxyz');
        }
        if (policy.useUppercase) {
            sets.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
        }
        if (policy.useNumbers) {
            sets.push('0123456789');
        }
        if (policy.useSpecial) {
            sets.push('+-=/\\');
        }

        if(sets.length == 0) {
            throw new Error(`Entry policy is invalid. No character sets are allowed.`);
        }

        let charactersPerSet = Math.ceil(policy.length / sets.length);

        let password = '';
        sets.forEach((set) => {
            for (let i = 0; i < charactersPerSet; i++) {
                password += set.charAt(Math.floor(Math.random() * set.length));
            }
        });
        password = shuffleString(password);
        password = password.slice(0, policy.length);

        entry = this.updateEntry(entry.name, null, password);

        this.modified = true;
        return entry;
    }

    allEntries(): ReadonlyArray<PasswordEntry> {
        return this.data.entries;
    }

    findEntries(nameStartsWith: string = ''): Array<PasswordEntry> {
        return this.data.entries.filter((entry) => entry.name.startsWith(nameStartsWith));
    }

    getEntry(name: string): PasswordEntry {
        return this.data.entries.find((entry) => entry.name == name);
    }

    addEntry(name: string, password: string, description: string = null, policyOverride: PasswordPolicy = {}): PasswordEntry {
        if (!/^[a-zA-Z0-9\-]+$/.test(name)) {
            throw new EvalError('Name must only contain alphabetic characters, numbers and dashes');
        }
        let entry = this.getEntry(name);
        if (entry) {
            throw new Error(`Entry ${name} already exists.`);
        }

        entry = {
            name: name,
            password: password,
            description: description || '',
            policyOverride: policyOverride,
        };
        this.data.entries.push(entry);

        this.modified = true;
        return entry;
    }

    /**
     * Update a password entry. Note that this creates and returns a new entry instance, as password entries are immutable.
     * @param name Name of the existing password entry
     * @param newName New name of the entry, or null if not changed
     * @param newPassword New password of the entry, or null if not changed
     * @param newDescription New description of the entry, or null if not changed
     * @param policyOverride New policy override of the entry, or null if not changed
     * 
     * @returns The updated entry
     */
    updateEntry(name: string, newName: string = null, newPassword: string = null, newDescription: string = null, policyOverride: PasswordPolicy = null): PasswordEntry {
        let entry = this.getEntry(name);
        if (!entry) {
            throw new Error(`Entry ${name} not found.`);
        }

        if (newName && !/^[a-zA-Z0-9\-]+$/.test(newName)) {
            throw new EvalError('Name must only contain alphabetic characters, numbers and dashes');
        }

        if(newName && this.getEntry(newName)) {
            throw new Error(`Entry ${newName} already exists.`);
        }

        let newEntry: PasswordEntry = {
            name: newName || entry.name,
            password: newPassword || entry.password,
            description: newDescription || entry.description,
            policyOverride: policyOverride || entry.policyOverride,
        };
        this.data.entries[this.data.entries.indexOf(entry)] = newEntry;

        this.modified = true;
        return newEntry;
    }

    removeEntry(name: string): PasswordEntry {
        let entry = this.getEntry(name);
        if (!entry) {
            throw new Error(`Entry ${name} not found.`);
        }

        this.data.entries = this.data.entries.filter((e) => e !== entry);
        this.modified = true;
        return entry;
    }

    /**
     * Serialize the password database and encrypt it with the master password.
     * @returns Data buffer containing the encrypted password database.
     */
    save(): Buffer {
        let iv = Buffer.from(crypto.randomBytes(16));
        let cypher = crypto.createCipheriv(algorithm, this.passwordHash + '0', iv);

        let sdata = JSON.stringify(this.data);
        let edata = Buffer.concat([cypher.update(sdata, 'utf8'), cypher.final()]);

        let bytes = Buffer.alloc(1 + iv.byteLength + 29 + 4 + edata.byteLength);
        let bOffset = 0;

        bytes.writeUInt8(iv.byteLength, bOffset);
        bOffset += 1;
        iv.copy(bytes, bOffset);
        bOffset += iv.byteLength;

        Buffer.from(this.passwordSalt).copy(bytes, bOffset);
        bOffset += 29;

        bytes.writeUInt32BE(edata.byteLength, bOffset);
        bOffset += 4;
        edata.copy(bytes, bOffset);

        this.modified = false;
        return bytes;
    }
}