(() => {

/** TEMPLATE **/

if (typeof module !== 'undefined') {
    module.exports = ChaCha20Poly1305;
} else {
    GLOBAL['ChaCha20Poly1305'] = ChaCha20Poly1305;
}

})()