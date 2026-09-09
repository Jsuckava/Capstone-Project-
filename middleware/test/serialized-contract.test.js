const test = require('node:test');
const assert = require('node:assert/strict');
const { serializeContractOperations } = require('../src/fabric/serialized-contract');

function cacheEntry() {
    return { activeOperations: 0, lastAccessed: 0, operationTail: Promise.resolve() };
}

test('Fabric operations for one cached identity are serialized', async () => {
    let active = 0;
    let maximumActive = 0;
    const rawContract = {
        async evaluateTransaction(_name, value) {
            active += 1;
            maximumActive = Math.max(maximumActive, active);
            await new Promise((resolve) => setTimeout(resolve, 10));
            active -= 1;
            return value;
        }
    };
    const state = cacheEntry();
    const contract = serializeContractOperations(rawContract, state);
    const results = await Promise.all(
        Array.from({ length: 8 }, (_, index) => contract.evaluateTransaction('Read', index))
    );

    assert.deepEqual(results, [0, 1, 2, 3, 4, 5, 6, 7]);
    assert.equal(maximumActive, 1);
    assert.equal(state.activeOperations, 0);
});

test('a failed Fabric operation does not block the following operation', async () => {
    const rawContract = {
        async submitTransaction(_name, value) {
            if (value === 'fail') throw new Error('expected failure');
            return value;
        }
    };
    const state = cacheEntry();
    const contract = serializeContractOperations(rawContract, state);
    const failed = contract.submitTransaction('Write', 'fail');
    const succeeded = contract.submitTransaction('Write', 'success');

    await assert.rejects(failed, /expected failure/);
    assert.equal(await succeeded, 'success');
    assert.equal(state.activeOperations, 0);
});
