#!/bin/bash
# Run Diff Analysis Pipeline
# Runs multiple models in both modes (VULNERABLE and PATCHED code) sequentially
#
# Dataset format (REVERSE DIFF: patched → vulnerable):
#   + lines = VULNERABLE code (what makes the code vulnerable)
#   - lines = PATCHED code (the security fix)
#
# Normal mode: analyze + lines (VULNERABLE) - should find vulnerability
# Reverse mode: analyze - lines (PATCHED) - should NOT find vulnerability

set -e

# Configuration
SAMPLES="${SAMPLES:-300}"
MAX_LINES="${MAX_LINES:-5000}"
SEED="${SEED:-42}"
UNIQUE_PACKAGES="${UNIQUE_PACKAGES:-true}"

# Dataset path
DATASET_PATH="${DATASET_PATH:-./diff_dataset}"

# Models to run (format: "model:provider")
MODELS=(
     "phi3:14b:ollama"
     "deepseek-coder-v2:16b:ollama"
     "qwen2.5-coder:32b:ollama"
     "mixtral:8x7b:ollama"
     "deepseek-r1:70b:ollama"
     "codegemma:7b:ollama"
     "codellama:70b:ollama"
     "llama3.3:ollama"
     "llama2:70b:ollama"
)

# Modes to run
MODES=("vulnerable" "patched")

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_BASE="${SCRIPT_DIR}/diff_analysis_results"

echo "=============================================="
echo "Diff Analysis Pipeline - Multi-Model Runner"
echo "=============================================="
echo "Dataset: ${DATASET_PATH}"
echo "  Reverse diff format: '+' = VULNERABLE, '-' = PATCHED"
echo ""
echo "Models: ${#MODELS[@]}"
for m in "${MODELS[@]}"; do
    echo "  - $m"
done
echo ""
echo "Modes:"
echo "  - vulnerable: check '+' lines (should find vulnerabilities)"
echo "  - patched: check '-' lines (should NOT find vulnerabilities)"
echo ""
echo "Samples per ecosystem: ${SAMPLES}"
echo "Max lines per diff: ${MAX_LINES}"
echo "Unique packages only: ${UNIQUE_PACKAGES}"
echo "=============================================="
echo ""

# Track progress
TOTAL_RUNS=$(( ${#MODELS[@]} * ${#MODES[@]} ))
CURRENT_RUN=0

# Run each model in each mode
for MODEL_SPEC in "${MODELS[@]}"; do
    # Parse model:provider (provider is after the LAST colon)
    PROVIDER="${MODEL_SPEC##*:}"
    # Model is everything before the last colon
    MODEL="${MODEL_SPEC%:*}"
    
    for MODE in "${MODES[@]}"; do
        CURRENT_RUN=$((CURRENT_RUN + 1))
        
        # Set mode flag and output directory
        if [ "$MODE" = "patched" ]; then
            MODE_FLAG="--reverse"
            MODE_DESC="PATCHED code (-) - expect: NOT vulnerable"
            OUTPUT_DIR="${RESULTS_BASE}/${MODEL}_patched"
        else
            MODE_FLAG=""
            MODE_DESC="VULNERABLE code (+) - expect: vulnerable"
            OUTPUT_DIR="${RESULTS_BASE}/${MODEL}_vulnerable"
        fi
        
        # Set unique packages flag
        if [ "$UNIQUE_PACKAGES" = "true" ]; then
            UNIQUE_FLAG="--unique-packages"
        else
            UNIQUE_FLAG=""
        fi
        
        echo ""
        echo "----------------------------------------------"
        echo "RUN ${CURRENT_RUN}/${TOTAL_RUNS}"
        echo "----------------------------------------------"
        echo "Model: ${MODEL}"
        echo "Provider: ${PROVIDER}"
        echo "Mode: ${MODE_DESC}"
        echo "Output: ${OUTPUT_DIR}"
        echo "----------------------------------------------"
        echo ""
        
        # Run the pipeline
        python3 "${SCRIPT_DIR}/main.py" \
            --dataset "${DATASET_PATH}" \
            --output "${OUTPUT_DIR}" \
            --model "${MODEL}" \
            --provider "${PROVIDER}" \
            --samples "${SAMPLES}" \
            --max-lines "${MAX_LINES}" \
            --seed "${SEED}" \
            ${MODE_FLAG} \
            ${UNIQUE_FLAG} \
            "$@"
        
        echo ""
        echo "✓ Completed: ${MODEL} / ${MODE}"
        echo ""
    done
done

echo ""
echo "=============================================="
echo "ALL RUNS COMPLETED"
echo "=============================================="
echo "Total runs: ${TOTAL_RUNS}"
echo "Results saved to: ${RESULTS_BASE}/"
echo ""
echo "Output directories:"
for MODEL_SPEC in "${MODELS[@]}"; do
    MODEL="${MODEL_SPEC%:*}"
    echo "  - ${MODEL}_vulnerable/"
    echo "  - ${MODEL}_patched/"
done
echo "=============================================="
