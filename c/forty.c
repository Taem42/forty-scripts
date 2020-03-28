#include <ctype.h>
#include "ckb_syscalls.h"
#include "protocol.h"
#include "common.h"
#include "stdio.h"

#define DATA_SIZE       32768 /* 32 KB */
#define SCRIPT_SIZE       32768 /* 32 KB */
#define WITNESS_SIZE      32768 /* 32 KB */
#define OUT_POINT_SIZE    36
#define HASH_SIZE         32

#define ERROR_FT_RULE1            42
#define ERROR_FT_RULE2            43
#define ERROR_LOAD_AMOUNT_HASH    44
#define ERROR_LOAD_PROOF          45

mol_seg_t current_script[SCRIPT_SIZE];
mol_seg_t current_script_hash[HASH_SIZE];

int pvm_hex2bin(char *s, unsigned char *buf)
{
    int i,n = 0;
    for(i = 0; s[i]; i += 2) {
        int c = tolower(s[i]);
        if(c >= 'a' && c <= 'f')
            buf[n] = c - 'a' + 10;
        else buf[n] = c - '0';
        if(s[i + 1] >= 'a' && s[i + 1] <= 'f')
            buf[n] = (buf[n] << 4) | (s[i + 1] - 'a' + 10);
        else buf[n] = (buf[n] << 4) | (s[i + 1] - '0');
        ++n;
    }
    return n;
}

/* ====== NOTES ===== 
 *
 * * TODO UDT unique identifier
 *
 * * FT rules
 *
 *   * Rule1: FT-input and FT-output are 1v1 and at the same index
 *   * Rule2: FT-input.amount >= FT-output.amount (verified by syscall zk42)
 *   * Rule3: Free to burn the FT
 *   * Rule4: Always success for admin's "issue" operations
 *
 * * FT OutputData format
 *
 *   ```
 *   [ amount_hash::Byte32, encrypted_amount::Bytes ]
 *   ```
 *
 * * Workflow
 *
 *   The script is positioned as FT type script. Hence here it should be an
 *   **output-type script** to do its verification jobs.
 *
 *     ```
 *     < normal checks ... >
 *     identifier := script.args[0:32]
 *     lock_hash = input.lock_hash
 *
 *     // "Issue" operation.
 *     IF identifier == lock_hash {
 *       RETURN CKB_SUCCESS
 *     }
 *
 *     // Next is "transfer" operation.
 *
 *     FOR (i, output) in ENUMERATE(outputs) {
 *       IF output.type_script.hash() == THE_CURRENT_SCRIPT_HASH {
 *         input = inputs[i]
 *         IF input.type_script.hash() != THE_CURRENT_SCRIPT_HASH {
 *           RETURN ERROR_RULE_1
 *         }
 *       }
 *      
 *       // Involve syscall "zk42" with the zk-proof fetched from witness
 *       input_amount_hash = input.data[0:32]
 *       output_amount_hash = output.data[0:32]
 *       witness = load_witness(i)
 *       zk_proof = witness.as_bytes()
 *       IF verify_zk_proof(input_amount_hash, output_amount_hash, zk_proof) {
 *         RETURN ERROR_RULE_2
 *       }
 *     }
 *
 *     RETURN CKB_SUCCESS
 *     ```
*/

int bin2hex(uint8_t *bin, uint8_t len, unsigned char* out)
{
	uint8_t  i;
	for (i=0; i<len; i++) {
		out[i*2]   = "0123456789abcdef"[bin[i] >> 4];
		out[i*2+1] = "0123456789abcdef"[bin[i] & 0x0F];
	}
	out[len*2] = '\0';
    return 0;
}

// Load the current script.
mol_seg_res_t load_current_script() {
  mol_seg_res_t script_seg_res;
  uint64_t len = SCRIPT_SIZE;
  int ret = ckb_load_script(current_script, &len, 0);
  if (ret != CKB_SUCCESS) {
    script_seg_res.errno = ret;
  } else if (len > SCRIPT_SIZE) {
    script_seg_res.errno = ERROR_SCRIPT_TOO_LONG;
  } else {
    script_seg_res.seg.ptr = (uint8_t *)current_script;
    script_seg_res.seg.size = len;

    if (MolReader_Script_verify(&script_seg_res.seg, false) != MOL_OK) {
      script_seg_res.errno = ERROR_ENCODING;
    } else {
      script_seg_res.errno = MOL_OK;
    }
  }
  return script_seg_res;
}

// Load the script-hash of the current script
mol_seg_res_t load_current_script_hash() {
  mol_seg_res_t script_hash_seg_res;
  uint64_t len = HASH_SIZE;
  int ret = ckb_load_script_hash(current_script_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    script_hash_seg_res.errno = ret;
  } else if (len != HASH_SIZE) {
    script_hash_seg_res.errno = ERROR_SYSCALL;
  } else {
    script_hash_seg_res.errno = MOL_OK;
    script_hash_seg_res.seg.ptr = (uint8_t *)current_script_hash;
    script_hash_seg_res.seg.size = len;
  }
  return script_hash_seg_res;
}

// Load the amount_hash from OutputData corresponding to the `index` and `source`
mol_seg_res_t load_amount_hash(unsigned char *output_data, size_t index, size_t source) {
  mol_seg_res_t output_data_seg_res;
  uint64_t len = DATA_SIZE;
  int ret = ckb_load_cell_data(
    (unsigned char *)output_data, &len, 0, index, source
  );
  if (ret != CKB_SUCCESS) {
    output_data_seg_res.errno = ret;
  } else if (len < HASH_SIZE) {
    output_data_seg_res.errno = ERROR_LOAD_AMOUNT_HASH;
  } else {
    output_data_seg_res.errno = MOL_OK;
    output_data_seg_res.seg.ptr = (uint8_t *)output_data;
    output_data_seg_res.seg.size = len;
  }

  if (MolReader_BytesVec_verify(&output_data_seg_res.seg, false) != MOL_OK) {
    output_data_seg_res.errno = ERROR_ENCODING;
    return output_data_seg_res;
  }

  mol_seg_res_t amount_hash_seg_res = MolReader_BytesVec_get(&output_data_seg_res.seg, 0);

  mol_seg_t bytes_seg = MolReader_Bytes_raw_bytes(&amount_hash_seg_res.seg);
  amount_hash_seg_res.seg = bytes_seg;

  return amount_hash_seg_res;
}

// Load zk-proof from witness at index `index`
mol_seg_res_t load_proof(unsigned char * witness, size_t index) {
  mol_seg_res_t proof_seg_res;
  uint64_t len = WITNESS_SIZE; // TODO Why not `0`?
  // TODO What the difference between CKB_SOURCE_INPUT and CKB_SOURCE_GROUP_INPUT
  // int ret = ckb_load_witness(witness, &len, 0, index, CKB_SOURCE_INPUT);
  int ret = ckb_load_witness(witness, &len, 0, index, CKB_SOURCE_INPUT);
  if (ret != CKB_SUCCESS) {
    proof_seg_res.errno = ERROR_LOAD_PROOF;
    return proof_seg_res;
  }

  mol_seg_t witness_seg;
  witness_seg.ptr = (uint8_t *)witness;
  witness_seg.size = len;

  if (MolReader_WitnessArgs_verify(&witness_seg, false) != MOL_OK) {
    proof_seg_res.errno = ERROR_LOAD_PROOF;
    return proof_seg_res;
  }

  // To raw bytes
  mol_seg_t output_type_seg = MolReader_WitnessArgs_get_output_type(&witness_seg);
  if (MolReader_BytesOpt_verify(&output_type_seg, false) != MOL_OK) {
    proof_seg_res.errno = ERROR_LOAD_PROOF;
    return proof_seg_res;
  }

  mol_seg_t bytes_seg = MolReader_Bytes_raw_bytes(&output_type_seg);
  proof_seg_res.errno = MOL_OK;
  proof_seg_res.seg = bytes_seg;
  return proof_seg_res;
}

// Verify zk-proof via syscall
int ft_verify(
    unsigned char * input_amount_hash,
    unsigned char * output_amount_hash,
    mol_seg_t proof_seg
) {
  return syscall(
    42,
    input_amount_hash,
    output_amount_hash,
    proof_seg.ptr,
    proof_seg.size,
    0, 0
  );
}

int ft_verify2() {
  uint8_t input_amount_hash[32];
  uint8_t output_amount_hash[32];
  uint8_t proof[128];
  pvm_hex2bin("e7b331d83f17550692fb998802b80dfb729a638052773f27ab3e1c7b09262e22", &input_amount_hash[0]);
  pvm_hex2bin("97490a5ee735719234aa0317a44d2e8962e76fe3273bb79124de4053dc4a2434", &output_amount_hash[0]);
  pvm_hex2bin("2de36a5b987c89b3b7de96a5d9563fccde1e5f9358371b098ec589c9ead54355867db0d4b674f3cd6b2f34b2266aec200a040f5beb80a5c1530262b27492d4911754b93046554fb44e9c871e4958e8461805c111ea5b000a01e35b076f74f7101d4cdf729302fbe4bdda37e17faaa9c81c5ac37bc1bbbefa71b0579fdffacfe8", &proof[0]);
  return syscall(
    42,
    input_amount_hash,
    output_amount_hash,
    proof,
    128,
    0, 0
  );
}

int main() {
  char debug[1000];
  unsigned char hex1[900];

  // Load current script
  mol_seg_res_t script_seg_res = load_current_script();
  if (script_seg_res.errno != MOL_OK) {
    return script_seg_res.errno;
  }

  // Load current script hash
  mol_seg_res_t script_hash_seg_res = load_current_script_hash();
  if (script_hash_seg_res.errno != MOL_OK) {
    return script_hash_seg_res.errno;
  }
  unsigned char *current_script_hash = script_hash_seg_res.seg.ptr;

  // Load current script args
  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg_res.seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  if (args_bytes_seg.size != HASH_SIZE) {
    return ERROR_ENCODING;
  }
  unsigned char * ft_identifier = args_bytes_seg.ptr;

  int ret = CKB_SUCCESS;
  for (size_t index = 0; ret == CKB_SUCCESS; index++) {
    unsigned char actual_script_hash[HASH_SIZE];
    uint64_t len = HASH_SIZE;

    ret = ckb_load_cell_by_field(
        actual_script_hash, &len, 0, index,
        CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_TYPE_HASH
    );

    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    } else if (ret == CKB_ITEM_MISSING) { // null type script
      continue;
    } else if (ret != CKB_SUCCESS) {
      return ret;
    } else if (len != HASH_SIZE) {
      return ERROR_SYSCALL;
    } else if (memcmp(actual_script_hash, current_script_hash, HASH_SIZE) != 0) {
      // Rule3: Free to burn FT. Hence here ignore non-FT output
      continue;
    }

    unsigned char lock_hash[HASH_SIZE];
    len = HASH_SIZE;
    ret = ckb_load_cell_by_field(
        lock_hash, &len, 0, index,
        CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_LOCK_HASH
    );
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    if (len != HASH_SIZE) {
      return ERROR_ENCODING;
    }

    if (memcmp(lock_hash, ft_identifier, HASH_SIZE) == 0) {
      // Rule4: Always success for admin's "issue" operations
      //
      // NOTICE: `continue` but not `break`! We should continue to verify the
      // other cells
      continue;
    }

    // We now know the output[index] is a FT cell

    // Rule1: FT input and FT output are 1v1 and at the same index
    ret = ckb_load_cell_by_field(
        actual_script_hash, &len, 0, index,
        CKB_SOURCE_INPUT, CKB_CELL_FIELD_TYPE_HASH
    );
    if (ret != CKB_SUCCESS) {
      return ret;
    } else if (len != HASH_SIZE) {
      return ERROR_SYSCALL;
    } else if (memcmp(actual_script_hash, current_script_hash, HASH_SIZE) != 0) {
      return ERROR_FT_RULE1;
    }

    // Rule2: FT-input.amount >= FT-output.amount (verified by syscall zk42)

    unsigned char in_data[DATA_SIZE];
    mol_seg_res_t input_amount_hash_seg_res = load_amount_hash(in_data, index, CKB_SOURCE_INPUT);
    if (input_amount_hash_seg_res.errno != MOL_OK) {
      return input_amount_hash_seg_res.errno;
    }
 
    unsigned char out_data[DATA_SIZE];
    mol_seg_res_t output_amount_hash_seg_res = load_amount_hash(out_data, index, CKB_SOURCE_OUTPUT);
    if (output_amount_hash_seg_res.errno != MOL_OK) {
      return output_amount_hash_seg_res.errno;
    }
 
    ckb_debug("........... load_proof");
    unsigned char witness[WITNESS_SIZE];
    mol_seg_res_t proof_seg_res = load_proof(witness, index);
    if (proof_seg_res.errno != MOL_OK) {
      return proof_seg_res.errno;
    }
 
    bin2hex(proof_seg_res.seg.ptr, proof_seg_res.seg.size, hex1);
    sprintf(debug, "......... proof.size: %d, proof: %s --", proof_seg_res.seg.size, hex1);
    ckb_debug(debug);
 
    ckb_debug(".......... start ft_verify");
    ret = ft_verify(
        input_amount_hash_seg_res.seg.ptr,
        output_amount_hash_seg_res.seg.ptr,
        proof_seg_res.seg
    );

    // ret = ft_verify2();

    if (ret != CKB_SUCCESS) {
      return ret;
    }
  }

  return CKB_SUCCESS;
}
