const sophis = require('../../../../nodejs/sophis');

sophis.initConsolePanicHook();

(async () => {

    let encrypted = sophis.encryptXChaCha20Poly1305("my message", "my_password");
    console.log("encrypted:", encrypted);
    let decrypted = sophis.decryptXChaCha20Poly1305(encrypted, "my_password");
    console.log("decrypted:", decrypted);

})();
