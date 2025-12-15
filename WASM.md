# WebAssembly (WASM) Support

This library can be compiled to WebAssembly for use in web browsers and Node.js.

## Prerequisites

Install `wasm-pack`:

```bash
cargo install wasm-pack
```

## Building for WebAssembly

### For Web Browsers

```bash
wasm-pack build --target web --out-dir pkg
```

This will create a `pkg` directory with:
- `foxchain_id.js` - JavaScript bindings
- `foxchain_id_bg.wasm` - The compiled WASM module
- TypeScript definitions
- Package metadata

### For Node.js

```bash
wasm-pack build --target nodejs --out-dir pkg-node
```

### For Both (Bundler)

```bash
wasm-pack build --target bundler --out-dir pkg-bundler
```

## Usage

### In a Web Browser

```html
<!DOCTYPE html>
<html>
<head>
    <title>Foxchain ID WASM Example</title>
</head>
<body>
    <h1>Blockchain Address Identifier</h1>
    <input type="text" id="address" placeholder="Enter address..." />
    <button onclick="identifyAddress()">Identify</button>
    <pre id="result"></pre>

    <script type="module">
        import init, { identify } from './pkg/foxchain_id.js';

        async function run() {
            await init();
            window.identifyAddress = function() {
                const input = document.getElementById('address').value;
                try {
                    const result = identify(input);
                    const candidates = JSON.parse(result);
                    document.getElementById('result').textContent = 
                        JSON.stringify(candidates, null, 2);
                } catch (error) {
                    document.getElementById('result').textContent = 
                        'Error: ' + error.message;
                }
            };
        }

        run();
    </script>
</body>
</html>
```

### In Node.js

```javascript
const { identify } = require('./pkg-node/foxchain_id.js');

// Note: In Node.js, you may need to initialize the module first
// depending on how wasm-pack generated the bindings

const result = identify("0xd8da6bf26964af9d7eed9e03e53415d37aa96045");
const candidates = JSON.parse(result);
console.log(candidates);
```

### With a Bundler (Webpack, Vite, etc.)

```javascript
import init, { identify } from 'foxchain-id/pkg-bundler/foxchain_id';

async function example() {
    // Initialize the WASM module
    await init();
    
    // Use the identify function
    const result = identify("0xd8da6bf26964af9d7eed9e03e53415d37aa96045");
    const candidates = JSON.parse(result);
    
    console.log('Candidates:', candidates);
}

example();
```

## API

### `identify(input: string): string`

Identifies blockchain addresses and returns a JSON string containing an array of candidates.

**Parameters:**
- `input` (string): The input string to identify (address, public key, etc.)

**Returns:**
- A JSON string containing an array of `IdentificationCandidate` objects

**Throws:**
- JavaScript error if identification fails

### IdentificationCandidate

```typescript
interface IdentificationCandidate {
    inputType: "address" | "publicKey";
    chain: string;
    encoding: "hex" | "base58" | "base58check" | "bech32" | "bech32m" | "ss58";
    normalized: string;
    confidence: number;  // 0.0 to 1.0
    reasoning: string;
}
```

## Example Output

```json
[
  {
    "inputType": "address",
    "chain": "ethereum",
    "encoding": "hex",
    "normalized": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
    "confidence": 1.0,
    "reasoning": "Valid EVM address with EIP-55 checksum"
  },
  {
    "inputType": "address",
    "chain": "polygon",
    "encoding": "hex",
    "normalized": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
    "confidence": 1.0,
    "reasoning": "Valid EVM address with EIP-55 checksum"
  }
]
```

## Publishing to npm

If you want to publish the WASM package to npm:

```bash
wasm-pack publish
```

This will publish the package to npm with the name specified in `Cargo.toml`.

## Performance

The WASM version provides near-native performance for address identification. The compiled WASM module is typically around 200-500KB (gzipped), depending on optimization settings.

## Optimization

For production builds, you can optimize the WASM binary:

```bash
wasm-pack build --target web --out-dir pkg --release
```

The `--release` flag enables optimizations. You can also use `wasm-opt` for further optimization:

```bash
wasm-opt -Os pkg/foxchain_id_bg.wasm -o pkg/foxchain_id_bg.wasm
```

## Browser Compatibility

The WASM build requires:
- Modern browsers with WebAssembly support
- ES6 modules support (for the web target)

All major browsers (Chrome, Firefox, Safari, Edge) support WebAssembly.

