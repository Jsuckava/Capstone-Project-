function serializeContractOperations(rawContract, cacheEntry) {
    return new Proxy(rawContract, {
        get(target, property, receiver) {
            if (property !== 'evaluateTransaction' && property !== 'submitTransaction') {
                const value = Reflect.get(target, property, receiver);
                return typeof value === 'function' ? value.bind(target) : value;
            }

            return (...args) => {
                const execute = async () => {
                    cacheEntry.activeOperations += 1;
                    cacheEntry.lastAccessed = Date.now();
                    try {
                        return await target[property](...args);
                    } finally {
                        cacheEntry.activeOperations -= 1;
                        cacheEntry.lastAccessed = Date.now();
                    }
                };
                const operation = cacheEntry.operationTail.then(execute, execute);
                cacheEntry.operationTail = operation.catch(() => undefined);
                return operation;
            };
        }
    });
}

module.exports = { serializeContractOperations };
