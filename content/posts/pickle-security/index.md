---
title: "The Security Risks of Loading PyTorch Models"
date: 2026-10-02
draft: false
tags: ["security", "machine-learning", "pytorch", "reverse-engineering"]
---

## 1. Introduction

In February 2025, security researchers at ReversingLabs uncovered **nullifAI**: two malicious PyTorch models hosted on Hugging Face that hid functional reverse shells inside serialized `.pt` weight files. When loaded via a standard `torch.load()`, the payloads delivered arbitrary code execution on model initialization. They evaded Hugging Face's [Picklescan](https://github.com/mmaitre314/picklescan) scanner for two reasons: the archives were compressed with 7z instead of PyTorch's default ZIP and the pickle files were deliberately "broken" so the scanner's parser failed while Python's more permissive unpickler still executed them. The two models reportedly went undetected for around eight months before disclosure.

This incident shows that model loading can introduce code-execution risks not just data-loading risks. Pattern matching alone is not sufficient to detect or prevent malicious payloads in model files.

> **Note:** All malicious examples in this post use a harmless `touch` payload and were run in an isolated VM. Nothing here is a working exploit.

## 2. torch.save() and torch.load()

### 2.1 torch.save()

PyTorch uses `torch.save()` to serialize an object and write it to a file. But it is not only about saving neural network weights. It can save many Python and PyTorch objects: a **tensor**, a **neural network model**, a **model's `state_dict`**, a **dictionary**, a **list or tuple** or even a **custom Python object**.

### 2.2 torch.load()

Conversely, `torch.load()` reads the serialized representation and reconstructs the Python and PyTorch object.

### 2.3 Where does pickle come in?

PyTorch's serialization mechanism relies on **Python's `pickle` serialization** for reconstructing Python objects. The security issue comes from the **deserialization step**. Python's pickle is not a format for storing passive data; its deserialization mechanism can invoke Python functionality while reconstructing objects. The mechanism that allows this is a special method Python looks for during pickling, called `__reduce__` which we cover in the next section.

## 3. The `__reduce__` method

Pickle needs to serialize objects that are not plain data, so the protocol lets an object define how to rebuild itself. Python checks for `__reduce__` when pickling. The method returns a tuple in the form `(callable, args_tuple)`. At load time, the unpickler executes `callable(*args_tuple)` to reconstruct the object, and since there is no constraint on what `callable` is, this introduces a vulnerability. It is possible because unpickling is not reading data; it is executing a sequence of instructions, which we will see directly in the disassembly below.

### 3.1 Benign example

```python
import pickle, pickletools

data = {"lr": 0.01, "epochs": 5}
pickletools.dis(pickle.dumps(data))
```

**Disassembly Output:**

```bash
$ python3 benign.py
    0: \x80 PROTO      5
    2: \x95 FRAME      30
   11: }    EMPTY_DICT
   12: \x94 MEMOIZE    (as 0)
   13: (    MARK
   14: \x8c     SHORT_BINUNICODE 'lr'
   18: \x94     MEMOIZE    (as 1)
   19: G        BINFLOAT   0.01
   28: \x8c     SHORT_BINUNICODE 'epochs'
   36: \x94     MEMOIZE    (as 2)
   37: K        BININT1    5
   39: u        SETITEMS   (from MARK)
   40: .    STOP
highest protocol among opcodes = 4
```

Every opcode here either builds a container (`EMPTY_DICT`, `SETITEMS`) or pushes literal data (`SHORT_BINUNICODE`, `BINFLOAT`, `BININT1`). There is no opcode that resolves an importable name and none that calls anything. Loading this can only ever produce the dict `{"lr": 0.01, "epochs": 5}`.

### 3.2 Malicious example

```python
import pickle, pickletools, os

class Evil:
    def __reduce__(self):
        return (os.system, ("touch /tmp/pwned",))

pickletools.dis(pickle.dumps(Evil()))
```

**Disassembly Output:**

```bash
$ python3 malicious.py
    0: \x80 PROTO      5
    2: \x95 FRAME      43
   11: \x8c SHORT_BINUNICODE 'posix'
   18: \x94 MEMOIZE    (as 0)
   19: \x8c SHORT_BINUNICODE 'system'
   27: \x94 MEMOIZE    (as 1)
   28: \x93 STACK_GLOBAL
   29: \x94 MEMOIZE    (as 2)
   30: \x8c SHORT_BINUNICODE 'touch /tmp/pwned'
   48: \x94 MEMOIZE    (as 3)
   49: \x85 TUPLE1
   50: \x94 MEMOIZE    (as 4)
   51: R    REDUCE
   52: \x94 MEMOIZE    (as 5)
   53: .    STOP
highest protocol among opcodes = 4
```

Disassembling the malicious pickle makes it clear what happens when the file is loaded. The first two instructions push the strings `'posix'` and `'system'` onto the stack. `STACK_GLOBAL` then uses these two values to resolve the function you wrote as `os.system`. The payload then pushes the command `'touch /tmp/pwned'` onto the stack. `TUPLE1` turns it into a one-element tuple which is the format `REDUCE` expects. `REDUCE` then takes the function and its arguments and calls the function, resulting in:

```bash
os.system("touch /tmp/pwned")
```

There is no vulnerability in these opcodes themselves. They are part of pickle’s normal behavior: `STACK_GLOBAL` resolves a callable, while `REDUCE` invokes it. The security issue comes from how these operations can be combined in a malicious payload.

One easy-to-miss detail is that the payload uses `posix` instead of `os`. Since `os.system` is backed by the `posix` module on this system, a scanner that only searches for `os.system` could miss it.

This shows why detecting malicious pickles is more difficult than simply looking for dangerous opcodes. PyTorch models also store pickle data inside ZIP archives and attackers can represent dangerous references in ways that simple string-based scanners may not detect.

## 4. Why static analysis on opcodes alone is not enough

### 4.1 A PyTorch file is not just a pickle

Since PyTorch 1.4, `torch.save()` uses a ZIP-based format. A typical `.pt` file contains:

```text
model.pt   (ZIP archive; members shown relative to the archive root)
├── model/data.pkl              ← pickle metadata / object structure
├── model/byteorder
├── model/data/
│   ├── 0                       ← tensor data
│   ├── 1
│   └── ...
├── model/version
└── model/.data/serialization_id
```

The important point is that `data.pkl` is only one part of the file. It describes how PyTorch should reconstruct the tensors, while the actual tensor bytes are stored separately.

Because the pickle is inside the ZIP archive, a scanner cannot treat the entire `.pt` file as a pickle. The file starts with the ZIP signature:

```text
PK\x03\x04
```

A scanner must first open the archive, find `data.pkl`, and then analyze that pickle:

```python
import zipfile

def extract_pickle(path):
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            name = next(n for n in z.namelist()
                        if n.endswith("data.pkl"))
            return z.read(name)
    return open(path, "rb").read()
```

The archive prefix (`model/` here) is not fixed across versions, which is why matching on `endswith("data.pkl")` is safer than assuming a specific directory.

Once extracted, the pickle can be disassembled normally. A typical model contains globals such as:

```text
GLOBAL → collections OrderedDict
GLOBAL → torch._utils _rebuild_tensor_v2
GLOBAL → torch FloatStorage
```

These are used with `REDUCE` to rebuild legitimate tensors.

This is the key security issue: legitimate and malicious pickles use the same mechanism. A real checkpoint may contain many `REDUCE` operations, so simply flagging `REDUCE` does not work. The scanner would have to determine whether each referenced global is safe.

There is also more than one way to encode global references. Older protocols use `GLOBAL`, while newer protocols (4 and above) can use `STACK_GLOBAL`, which pushes the module and name as separate strings before resolving them. A scanner must handle both.

Ultimately, the problem is not the presence of `REDUCE`; it is the ability to resolve and call arbitrary functions. This is why restricting that capability is more reliable than trying to detect every malicious pickle.

## 5. Fixes

The sections above lead to one conclusion: you cannot reliably determine whether a pickle is safe by scanning it. The dangerous ability to resolve and call arbitrary functions is also essential for rebuilding legitimate objects. So instead of improving the scanner, the safer solution is to remove this capability. There are two ways to do that.

### 5.1 weights_only=True

With `weights_only=True`, PyTorch uses a restricted unpickler instead of the standard one. It only allows trusted types and PyTorch's own tensor-rebuilding functions. Dangerous functions such as `posix.system`, `builtins.exec`, or `subprocess.Popen` are blocked. When the malicious checkpoint tries to resolve `posix.system`, loading stops before the function can be called and `/tmp/pwned` is never created. This removes the dangerous function-calling capability instead of trying to detect malicious files.

One caveat: `weights_only=True` only became the **default in PyTorch 2.6**. On earlier versions (the demo here ran on 2.3.1) the default is still `weights_only=False`, so you should set it explicitly rather than rely on the default.

### 5.2 safetensors

`weights_only=True` makes pickle safer by restricting what it can execute. `safetensors` takes a different approach: **it avoids pickle entirely**.

A `safetensors` file contains a small JSON header describing each tensor's name, shape, dtype and location followed by the raw tensor bytes:

```text
┌─────────────────────────────┐
│ JSON header                 │
│ name → shape, dtype, offset │
├─────────────────────────────┤
│ Raw tensor bytes            │
└─────────────────────────────┘
```

Unlike pickle, which contains instructions for **how to reconstruct objects**, `safetensors` only describes **what the tensors are and where their data is**. There are no opcodes such as `GLOBAL` or `REDUCE`, no function resolution and no arbitrary Python objects to reconstruct.

```python
from safetensors.torch import save_file, load_file

save_file(model.state_dict(), "model.safetensors")
state = load_file("model.safetensors")
```

Here, `state` is simply a mapping of parameter names to tensors:

```text
"fc1.weight" → Tensor
"fc1.bias"   → Tensor
"fc2.weight" → Tensor
```

The trade-off is that `safetensors` only supports tensors and their metadata. It cannot store arbitrary Python objects or the instructions needed to reconstruct them. This makes it safer for model weights because loading the file does not involve executing Python code.


## Resources

**The nullifAI incident**
* [ReversingLabs: Malicious ML models discovered on Hugging Face platform](https://www.reversinglabs.com/blog/rl-identifies-malware-ml-model-hosted-on-hugging-face)

**Pickle format and tooling**
* [Python Docs: pickle library and security warnings](https://docs.python.org/3/library/pickle.html)
* [Python Docs: pickletools library](https://docs.python.org/3/library/pickletools.html)
* [GitHub: picklescan scanner](https://github.com/mmaitre314/picklescan)
* [GitHub: fickling analysis and decompilation tool](https://github.com/trailofbits/fickling)

**PyTorch and safe loading**
* [PyTorch Docs: torch.load and weights_only parameter](https://pytorch.org/docs/stable/generated/torch.load.html)
* [PyTorch Docs: Serialization notes](https://pytorch.org/docs/stable/notes/serialization.html)
* [GitHub: safetensors format and documentation](https://github.com/huggingface/safetensors)

**Background reading**
* Johann Rehberger: Machine Learning Attack Series: Backdooring Pickle Files (2022)
* Evan Sangaline: Dangerous Pickles — malicious Python serialization (2017)