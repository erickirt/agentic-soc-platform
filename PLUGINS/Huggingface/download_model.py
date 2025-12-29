# uncomment the code to set a custom Hugging Face endpoint if needed. this must run on the top of the script
import os

os.environ["HF_ENDPOINT"] = "https://hf-mirror.com"
# os.environ['HTTP_PROXY'] = 'http://127.0.0.1:7890'
# os.environ['HTTPS_PROXY'] = 'http://127.0.0.1:7890'

import os

from fastembed import SparseTextEmbedding
from huggingface_hub import snapshot_download

from Lib.configs import BASE_DIR

if __name__ == "__main__":
    # download reranker model (BAAI/bge-reranker-v2-m3)
    model_id = "BAAI/bge-reranker-v2-m3"
    local_dir = os.path.join(BASE_DIR, 'Docker', 'Huggingface', '../../Docker/Huggingface/bge-reranker-v2-m3')
    snapshot_download(repo_id=model_id, local_dir=local_dir)
    print("Reranker model downloaded to:", local_dir)
    # download sparse model (bm25)
    cache_dir = os.path.join(BASE_DIR, 'Docker', 'Huggingface', '../../Docker/Huggingface/bm25')

    model = SparseTextEmbedding(model_name="Qdrant/bm25", cache_dir=cache_dir)
    print("Sparse model downloaded to:", cache_dir)
