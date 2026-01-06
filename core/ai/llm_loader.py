from functools import lru_cache
from llama_cpp import Llama

@lru_cache(maxsize=1)
def load_llm(
    model_path: str,
    n_ctx: int = 1024,
    n_threads: int = 4,
    n_batch: int = 128,
):
    return Llama(
        model_path=model_path,
        n_ctx=n_ctx,
        n_threads=n_threads,
        n_batch=n_batch,
        f16_kv=True,
        logits_all=False,
        verbose=False,
    )
