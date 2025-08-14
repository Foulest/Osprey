/*
 * Osprey - a browser extension that protects you from malicious websites.
 * Copyright (C) 2025 Foulest (https://github.com/Foulest)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
"use strict";

// Utility module for SmartScreen hashing operations.
const SmartScreenUtil = (() => {

    const hashConstants = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9,
        14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    ];

    const md5Constants = [
        3614090360, 3905402710, 606105819, 3250441966, 4118548399, 1200080426, 2821735955, 4249261313,
        1770035416, 2336552879, 4294925233, 2304563134, 1804603682, 4254626195, 2792965006, 1236535329,
        4129170786, 3225465664, 643717713, 3921069994, 3593408605, 38016083, 3634488961, 3889429448,
        568446438, 3275163606, 4107603335, 1163531501, 2850285829, 4243563512, 1735328473, 2368359562,
        4294588738, 2272392833, 1839030562, 4259657740, 2763975236, 1272893353, 4139469664, 3200236656,
        681279174, 3936430074, 3572445317, 76029189, 3654602809, 3873151461, 530742520, 3299628645,
        4096336452, 1126891415, 2878612391, 4237533241, 1700485571, 2399980690, 4293915773, 2240044497,
        1873313359, 4264355552, 2734768916, 1309151649, 4149444226, 3174756917, 718787259, 3951481745
    ];

    /**
     * Rotates the bits of a value to the left.
     *
     * @param {number} value - The value to rotate.
     * @param {number} shift - The number of bits to shift.
     * @returns {number} The rotated value.
     */
    function rotateBits(value, shift) {
        return value << shift | value >>> 32 - shift;
    }

    /**
     * Computes the MD5 hash of the input string.
     *
     * @param input - The input string to hash.
     * @returns {[number,number,number,number]} - The MD5 hash as an array of four integers.
     */
    function computeHash(input) {
        let hashValue;
        let intermediateValue;
        let paddedInput = input;
        let inputLength = 8 * paddedInput.length;

        // Appends 1 bit and necessary padding
        paddedInput += String.fromCharCode(128);
        while ((paddedInput.length + 8) % 64) {
            paddedInput += String.fromCharCode(0);
        }

        // Appends the length of the input
        for (let index = 0; index < 8; index++) {
            paddedInput += index < 4 ? String.fromCharCode(inputLength >>> 8 * index & 255) : String.fromCharCode(0);
        }

        let numberOfWords = paddedInput.length / 4;

        let getWord = function (index) {
            const wordIndex = 4 * index;
            return paddedInput.charCodeAt(wordIndex)
                | paddedInput.charCodeAt(wordIndex + 1) << 8
                | paddedInput.charCodeAt(wordIndex + 2) << 16
                | paddedInput.charCodeAt(wordIndex + 3) << 24;
        };

        // Initializes the hash variables
        let a = 1732584193;
        let b = 4023233417;
        let c = 2562383102;
        let d = 271733878;

        // Processes each block of the padded input
        for (let blockIndex = 0; blockIndex < numberOfWords; blockIndex += 16) {
            let A = a;
            let B = b;
            let C = c;
            let D = d;

            for (let roundIndex = 0; roundIndex < 64; roundIndex++) {
                if (roundIndex < 16) {
                    hashValue = B & C | ~B & D;
                    intermediateValue = roundIndex;
                } else if (roundIndex < 32) {
                    hashValue = D & B | ~D & C;
                    intermediateValue = (5 * roundIndex + 1) % 16;
                } else if (roundIndex < 48) {
                    hashValue = B ^ C ^ D;
                    intermediateValue = (3 * roundIndex + 5) % 16;
                } else {
                    hashValue = C ^ (B | ~D);
                    intermediateValue = 7 * roundIndex % 16;
                }

                hashValue = hashValue + A + md5Constants[roundIndex] + getWord(blockIndex + intermediateValue);
                A = D;
                D = C;
                C = B;
                B += rotateBits(hashValue, hashConstants[roundIndex]);
            }

            a += A;
            b += B;
            c += C;
            d += D;
        }
        return [a, b, c, d];
    }

    /**
     * Converts an array of integers to a string representation.
     *
     * @param array - The array of integers to convert.
     * @returns {string} - The string representation of the array.
     */
    function intArrayToString(array) {
        let resultString = "";

        for (let index = 0, length = array.length; index < length; index++) {
            const value = array[index];
            resultString += String.fromCharCode(value & 255);
            resultString += String.fromCharCode(value >>> 8 & 255);
            resultString += String.fromCharCode(value >>> 16 & 255);
            resultString += String.fromCharCode(value >>> 24 & 255);
        }
        return resultString;
    }

    /**
     * Reverses the bits of a 32-bit integer.
     *
     * @param value - The 32-bit integer to reverse.
     * @returns {*} - The integer with its bits reversed.
     */
    function reverseBits(value) {
        return (value >>> 16) + (value << 16);
    }

    /**
     * Performs a hash operation on the state using the provided multipliers.
     *
     * @param state - The state object containing the buffer and index.
     * @param mult1 - The first multiplier for the hash operation.
     * @param mult2 - The second multiplier for the hash operation.
     * @param mult3 - The third multiplier for the hash operation.
     * @param mult4 - The fourth multiplier for the hash operation.
     * @param mult5 - The fifth multiplier for the hash operation.
     */
    function hashOperation(state, mult1, mult2, mult3, mult4, mult5) {
        state.t += state.buffer.getWord(state.index++);
        state.t = Math.imul(state.t, mult1) + Math.imul(reverseBits(state.t), mult2);
        state.t = Math.imul(reverseBits(state.t), mult3) + Math.imul(state.t, mult4);
        state.t += Math.imul(reverseBits(state.t), mult5);
        state.sum += state.t;
    }

    /**
     * Performs an extended hash operation on the state using the provided multipliers.
     *
     * @param state - The state object containing the buffer and index.
     * @param mult1 - The first multiplier for the hash operation.
     * @param mult2 - The second multiplier for the hash operation.
     * @param mult3 - The third multiplier for the hash operation.
     * @param mult4 - The fourth multiplier for the hash operation.
     * @param mult5 - The fifth multiplier for the hash operation.
     * @param mult6 - The sixth multiplier for the hash operation.
     */
    function hashOperationExtended(state, mult1, mult2, mult3, mult4, mult5, mult6) {
        state.t += state.buffer.getWord(state.index++);
        state.t = Math.imul(state.t, mult1);
        state.u = reverseBits(state.t);
        state.t = Math.imul(state.u, mult2);
        state.t = Math.imul(reverseBits(state.t), mult3);
        state.t = Math.imul(reverseBits(state.t), mult4);
        state.t = Math.imul(reverseBits(state.t), mult5);
        state.t += Math.imul(state.u, mult6);
        state.sum += state.t;
    }

    /**
     * Generates a hash for the given input string.
     *
     * @param input - The input string to hash.
     * @returns {{key: string, hash: string}} - An object containing the base64 encoded key and hash.
     */
    function hash(input) {
        const hashOutput = computeHash(input);

        const outputData = {
            length: input.length / 4 & -2, getWord(index) {
                const wordIndex = 4 * index;
                return input.charCodeAt(wordIndex)
                    | input.charCodeAt(wordIndex + 1) << 8
                    | input.charCodeAt(wordIndex + 2) << 16
                    | input.charCodeAt(wordIndex + 3) << 24;
            }
        };

        const intermediateOutput = [0, 0];
        const finalOutput = [0, 0];

        /**
         * Performs the first half of the hash calculation.
         *
         * @param {Object} inputBuffer - The input buffer containing the data to hash.
         * @param {Array} hashArray - The array containing hash constants.
         * @param {Array} output - The output array to store the hash result.
         */
        if (((inputBuffer, hashArray, output) => {
            let hashState = {
                buffer: inputBuffer,
                index: 0,
                sum: 0,
                t: 0
            };

            let firstMultiplier = 1 | hashArray[0];
            let secondMultiplier = 1 | hashArray[1];

            // Ensures the input buffer is valid
            if (inputBuffer.length < 2 || 1 & inputBuffer.length) {
                return false;
            }

            // Processes the buffer until all words are consumed
            while (hashState.buffer.length - hashState.index > 1) {
                hashOperation(hashState, firstMultiplier, 4010109435, 1755016095, 240755605, 3287280279);
                hashOperation(hashState, secondMultiplier, 3273069531, 3721207567, 984919853, 901586633);
            }

            output[0] = hashState.t;
            output[1] = hashState.sum;
            return true;
        })(outputData, hashOutput, finalOutput)) {
            const additionalOutput = [0, 0];

            /**
             * Performs the second half of the hash calculation.
             *
             * @param {Object} inputBuffer - The input buffer containing the data to hash.
             * @param {Array} hashArray - The array containing hash constants.
             * @param {Array} output - The output array to store the hash result.
             */
            ((inputBuffer, hashArray, output) => {
                let hashState = {
                    buffer: inputBuffer,
                    index: 0,
                    sum: 0,
                    t: 0,
                    u: 0
                };

                let firstMultiplier = 1 | hashArray[0];
                let secondMultiplier = 1 | hashArray[1];

                // Ensures the input buffer is valid
                if (inputBuffer.length < 2 || 1 & inputBuffer.length) {
                    return false;
                }

                // Processes the buffer until all words are consumed
                while (hashState.buffer.length - hashState.index > 1) {
                    hashOperationExtended(hashState, firstMultiplier, 3482890513, 2265471903, 315537773, 629022083, 0);
                    hashOperationExtended(hashState, secondMultiplier, 2725517045, 3548616447, 2090019721, 3215236969, 0);
                }

                output[0] = hashState.t;
                output[1] = hashState.sum;
                return true;
            })(outputData, hashOutput, additionalOutput) &&
            (intermediateOutput[0] = finalOutput[0] ^ additionalOutput[0],
                intermediateOutput[1] = finalOutput[1] ^ additionalOutput[1]);
        }

        return {
            key: btoa(intArrayToString(hashOutput)),
            hash: btoa(intArrayToString(intermediateOutput))
        };
    }

    return {
        hash
    };
})();
