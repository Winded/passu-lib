import { expect } from 'chai';
import 'mocha';
import { PasswordDatabase } from '../src/passu';

describe('PasswordDatabase', () => {
    context('Default policy', () => {
        it('should update default policy', () => {
            let pwInput = 'testpassword';
    
            let db = new PasswordDatabase(pwInput);
            db.defaultPolicy = {
                length: 16,
                useLowercase: false,
                useUppercase: true,
                useNumbers: true,
                useSpecial: true,
            };
            
            expect(db.defaultPolicy.length).to.eq(16);
            expect(db.defaultPolicy.useLowercase).to.eq(false);
            expect(db.defaultPolicy.useUppercase).to.eq(true);
            expect(db.defaultPolicy.useNumbers).to.eq(true);
            expect(db.defaultPolicy.useSpecial).to.eq(true);
        });
    });
    
    context('Database encryption and decryption', () => {
        it('should encrypt and decrypt the database successfully', () => {
            let pwInput = 'testpassword';
    
            let db = new PasswordDatabase(pwInput);
            db.addEntry('test', 'mypassword', 'description');
    
            let bytes = db.save();
    
            let decryptedDb = PasswordDatabase.fromData(bytes, pwInput);
            let entry = decryptedDb.getEntry('test');
            
            expect(entry.name).to.eq('test');
            expect(entry.password).to.eq('mypassword');
            expect(entry.description).to.eq('description');
        });
        it('should decrypt and re-encrypt with another password successfully', () => {
            let pwInput = 'testpassword';
            let pwInput2 = 'anotherpassword';
    
            let db = new PasswordDatabase(pwInput);
            db.addEntry('test', 'mypassword', 'description');
    
            let bytes = db.save();
    
            db = PasswordDatabase.fromData(bytes, pwInput);
            db.password = pwInput2;
            bytes = db.save();

            let decryptedDb = PasswordDatabase.fromData(bytes, pwInput2);
            let entry = decryptedDb.getEntry('test');
            
            expect(entry.name).to.eq('test');
            expect(entry.password).to.eq('mypassword');
            expect(entry.description).to.eq('description');
        });
    });
    
    context('Add/Edit/Delete entries', () => {
        it('should successfully add an entry', () => {
            let pwInput = 'testpassword';
    
            let db = new PasswordDatabase(pwInput);
            let entry = db.addEntry('test', 'its a password134125+-++\\/', 'description');
            entry = db.getEntry('test');
    
            expect(entry).to.not.eq(undefined);
            expect(entry.password).to.eq('its a password134125+-++\\/');
            expect(entry.description).to.eq('description');
        });
        it('should fail when entry has invalid name', () => {
            let pwInput = 'testpassword';
    
            let db = new PasswordDatabase(pwInput);
            
            expect(() => {
                db.addEntry('test+test space', 'its a password134125+-++\\/', 'description');
            }).to.throw(EvalError, 'Name must only contain alphabetic characters, numbers and dashes');
        });
        it('should fail when duplicate entry is added', () => {
            let pwInput = 'testpassword';
    
            let db = new PasswordDatabase(pwInput);
            db.addEntry('test', 'its a password134125+-++\\/', 'description');
    
            expect(() => {
                db.addEntry('test', 'its a password134125+-++\\/', 'description');
            }).to.throw('Entry test already exists.')
        });
        it('should successfully edit an entry', () => {
            let pwInput = 'testpassword';
    
            let db = new PasswordDatabase(pwInput);
            let entry = db.addEntry('test', 'its a password134125+-++\\/', 'description');
            entry = db.getEntry('test');
    
            expect(entry).to.not.eq(undefined);
            expect(entry.password).to.eq('its a password134125+-++\\/');
            expect(entry.description).to.eq('description');
    
            db.updateEntry('test', 'test1', 'newpassword', 'another description', {
                useNumbers: false,
            });
            entry = db.getEntry('test1');
    
            expect(entry).to.not.eq(undefined);
            expect(entry.password).to.eq('newpassword');
            expect(entry.description).to.eq('another description');
            expect(entry.policyOverride.useNumbers).to.eq(false);
        });
        it('should successfully delete an entry', () => {
            let pwInput = 'testpassword';
    
            let db = new PasswordDatabase(pwInput);
            let entry = db.addEntry('test', 'its a password134125+-++\\/', 'description');
            entry = db.getEntry('test');
    
            expect(entry).to.not.eq(null);
            expect(entry.password).to.eq('its a password134125+-++\\/');
            expect(entry.description).to.eq('description');
    
            db.removeEntry('test');
            entry = db.getEntry('test');
    
            expect(entry).to.eq(undefined);
        });
    });
    
    context('Password generation', () => {
        it('should generate password with default password policy', () => {
            let pwInput = 'testpassword';
    
            let db = new PasswordDatabase(pwInput);
            db.addEntry('test', '', 'description');
            let entry = db.generatePassword('test');
            
            expect(entry.password.length).to.eq(32);
            expect(/[a-z]/.test(entry.password)).to.eq(true);
            expect(/[A-Z]/.test(entry.password)).to.eq(true);
            expect(/[0-9]/.test(entry.password)).to.eq(true);
            expect(/[\+\-\=\/\\]/.test(entry.password)).to.eq(true);
        });
    
        it('should generate password with updated default password policy', () => {
            let pwInput = 'testpassword';
    
            let db = new PasswordDatabase(pwInput);
            db.defaultPolicy = {
                length: 20,
                useLowercase: true,
                useUppercase: true,
                useNumbers: true,
                useSpecial: false,
            };
    
            db.addEntry('test', '', 'description');
            let entry = db.generatePassword('test');
            
            expect(entry.password.length).to.eq(20);
            expect(/[a-z]/.test(entry.password)).to.eq(true);
            expect(/[A-Z]/.test(entry.password)).to.eq(true);
            expect(/[0-9]/.test(entry.password)).to.eq(true);
            expect(/[\+\-\=\/\\]/.test(entry.password)).to.eq(false);
        });
    
        it('should generate password with specified password policy', () => {
            let pwInput = 'testpassword';
    
            let db = new PasswordDatabase(pwInput);
            db.addEntry('test', '', 'description', {
                length: 16,
                useLowercase: true,
                useUppercase: false,
                useNumbers: true,
                useSpecial: false,
            });
            let entry = db.generatePassword('test');
            
            expect(entry.password.length).to.eq(16);
            expect(/[a-z]/.test(entry.password)).to.eq(true);
            expect(/[A-Z]/.test(entry.password)).to.eq(false);
            expect(/[0-9]/.test(entry.password)).to.eq(true);
            expect(/[\+\-\=\/\\]/.test(entry.password)).to.eq(false);
        });
    
        it('should generate password with partially default password policy', () => {
            let pwInput = 'testpassword';
    
            let db = new PasswordDatabase(pwInput);
            db.addEntry('test', '', 'description', {
                length: 8,
                useLowercase: false,
            });
            let entry = db.generatePassword('test');
            
            expect(entry.password.length).to.eq(8);
            expect(/[a-z]/.test(entry.password)).to.eq(false);
            expect(/[A-Z]/.test(entry.password)).to.eq(true);
            expect(/[0-9]/.test(entry.password)).to.eq(true);
            expect(/[\+\-\=\/\\]/.test(entry.password)).to.eq(true);
        });
    });
});