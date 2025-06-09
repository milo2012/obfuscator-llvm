#include "StringObfuscation.h"
#include "string/decode.h"
#include "utils/Utils.h"
#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/Analysis/LazyValueInfo.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/Utils.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include <llvm/IRReader/IRReader.h>
#include <llvm/Transforms/Utils/ModuleUtils.h>

#include "utils/CryptoUtils.h"

static const unsigned int RandomNameMinSize = 5;
static const unsigned int RandomMaxNameSize = 15;
static const char ALPHANUM[] =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

using namespace llvm;

namespace llvm {
ConstantDataArray *StringObfuscatorPass::encodeStringDataArray(LLVMContext &ctx,
                                                               const char *str,
                                                               size_t size,
                                                               uint8_t key) {
  // Check this is a valid string (not containing zeros)
  if (str[size - 1] == '\0') {
    if (strnlen(str, size) != size - 1)
      return nullptr;
  } else {
    if (strnlen(str, size) != size)
      return nullptr;
  }

  // Encode the data
  char *encodedStr = (char *)malloc(size);
  for (unsigned int i = 0; i < size; i++) {
    encodedStr[i] = str[i] ^ key;
  }

  // Update the value
  auto encodedRef = StringRef(encodedStr, size);

  // Return a new ConstantDataArray
  return static_cast<ConstantDataArray *>(
      ConstantDataArray::getString(ctx, encodedRef, false));
}

void StringObfuscatorPass::encodeGlobalString(LLVMContext &ctx,
                                              GlobalVariable *gv,
                                              ConstantDataArray *array) {
  StringRef ref = array->getAsString();
  const char *str = ref.data();
  const unsigned int size = ref.size();

  uint8_t key = cryptoutils->get_uint8_t();
  auto encodedArray = encodeStringDataArray(ctx, str, size, key);
  if (encodedArray != nullptr) {
    gv->setInitializer(encodedArray);
    gv->setConstant(false);
    this->globalStrings.push_back(
        GlobalStringVariable(gv, size, 0, false, key));
  }
}

void StringObfuscatorPass::encodeStructString(LLVMContext &ctx,
                                              GlobalVariable *gv,
                                              ConstantStruct *cs,
                                              ConstantDataArray *array,
                                              unsigned int index) {
  StringRef ref = array->getAsString();
  const char *str = ref.data();
  const unsigned int size = ref.size();

  uint8_t key = llvm::cryptoutils->get_uint8_t();
  auto encodedArray = encodeStringDataArray(ctx, str, size, key);
  if (encodedArray != nullptr) {
    cs->setOperand(index, encodedArray);
    gv->setConstant(false);
    this->globalStrings.push_back(
        GlobalStringVariable(gv, size, index, true, key));
  }
}

StringObfuscatorPass::StringObfuscatorPass() {}

bool StringObfuscatorPass::encodeAllStrings(Module &M) {
  auto &ctx = M.getContext();

  // For each global variable
  for (GlobalVariable &gv : M.globals()) {
    if (!gv.isConstant()                         // constant
        || !gv.hasInitializer()                  // unitialized
        || gv.hasExternalLinkage()               // external
        || gv.getSection() == "llvm.metadata") { // Intrinsic Global Variables
      //|| gv.getSection().find("__objc_methname") != string::npos) { // TODO :
      // is this necessary ?
      continue;
    }

    // Get the variable value
    Constant *initializer = gv.getInitializer();

    // Encode the value and update the variable
    if (isa<ConstantDataArray>(initializer)) { // Global variable
      auto array = cast<ConstantDataArray>(initializer);
      if (array->isString()) {
        encodeGlobalString(ctx, &gv, array);
      }
    } else if (isa<ConstantStruct>(initializer)) { // Variable in a struct
      auto cs = cast<ConstantStruct>(initializer);
      for (unsigned int i = 0; i < initializer->getNumOperands(); i++) {
        auto operand = cs->getOperand(i);
        if (isa<ConstantDataArray>(operand)) {
          auto array = cast<ConstantDataArray>(operand);
          if (array->isString()) {
            encodeStructString(ctx, &gv, cs, array, i);
          }
        }
      }
    }
  }

  return !this->globalStrings.empty();
}

std::string StringObfuscatorPass::generateRandomName() {
  std::string name = "";
  auto charsetSize = strlen(ALPHANUM) - 1;

  auto size =
      MIN(cryptoutils->get_uint8_t() + RandomNameMinSize, RandomMaxNameSize);
  for (unsigned int i = 0; i < size; i++) {
    auto index = cryptoutils->get_range(charsetSize);
    name += ALPHANUM[index];
  }

  return name;
}

Function *StringObfuscatorPass::addDecodeFunction(Module &M) {
  auto &ctx = M.getContext();

  // Parse the bitcode from the header (creates a new module which contains
  // the decode function)
  SMDiagnostic err;
  auto buf = MemoryBuffer::getMemBuffer(
      StringRef(reinterpret_cast<const char *>(decode_c_bc), decode_c_bc_len),
      "", false);
  std::unique_ptr<Module> decodeModule =
      parseIR(buf->getMemBufferRef(), err, ctx);
  Function *loadedFunction = decodeModule->getFunction("decodeString");

  // Declare the decode function in M with the same signature as the loaded
  // function
  auto functionName = generateRandomName();
  M.getOrInsertFunction(functionName, loadedFunction->getFunctionType());
  Function *declaredFunction = M.getFunction(functionName);

  // Map the declared and loaded functions arguments
  ValueToValueMapTy vmap;
  auto larg = loadedFunction->arg_begin();
  for (auto darg = declaredFunction->arg_begin();
       darg != declaredFunction->arg_end(); darg++) {
    vmap[&*larg] = &*darg;
    larg++;
  }

  // Copy the loaded function into the empty declared function (in the proper
  // module)
  SmallVector<ReturnInst *, 8> returns;
  ClonedCodeInfo codeInfo;
  CloneFunctionInto(declaredFunction, loadedFunction, vmap,
#if LLVM_VERSION_MAJOR < 13
                    true,
#else
                    CloneFunctionChangeType::DifferentModule,
#endif
                    returns, "", &codeInfo);

  return declaredFunction;
}

Function *StringObfuscatorPass::addDecodeAllStringsFunction(Module &M, Function *decodeFn) {
  LLVMContext &ctx = M.getContext();

  std::string name = generateRandomName();
  FunctionType *funcTy = FunctionType::get(Type::getVoidTy(ctx), false);
  Function *func = Function::Create(funcTy, Function::InternalLinkage, name, &M);
  func->setCallingConv(CallingConv::C);

  BasicBlock *entryBB = BasicBlock::Create(ctx, "entry", func);
  IRBuilder<> builder(entryBB);

  for (const auto &entry : this->globalStrings) {
    Value *gv = entry.var;
    Value *ptr = gv;

    if (entry.isStruct) {
      ptr = builder.CreateStructGEP(gv->getType()->getPointerElementType(), gv, entry.index);
    }

    ptr = builder.CreateConstInBoundsGEP2_32(ptr->getType()->getPointerElementType(), ptr, 0, 0);
    Value *size = ConstantInt::get(Type::getInt32Ty(ctx), entry.size);
    Value *key  = ConstantInt::get(Type::getInt8Ty(ctx), entry.key);

    builder.CreateCall(decodeFn, {ptr, size, key});
  }

  builder.CreateRetVoid();

  llvm::appendToGlobalCtors(M, func, 0);
  return func;
}


PreservedAnalyses StringObfuscatorPass::run(Module &M,
                                            ModuleAnalysisManager &MAM) {
  // Encode all the global strings
  if (!encodeAllStrings(M)) {
    return PreservedAnalyses::all();
  }

  // Insert a function to decode a string
  Function *decodeFunction = addDecodeFunction(M);

  // Insert a function decoding all the strings in global constructors
  addDecodeAllStringsFunction(M, decodeFunction);

  return PreservedAnalyses::none();
}
} // namespace llvm
