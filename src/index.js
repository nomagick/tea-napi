const bindings = require('bindings')('tea_napi');

module.exports = {
    ...bindings,
    default: bindings
};