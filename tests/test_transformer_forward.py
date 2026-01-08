import torch

from ml.models.transformer import SimpleVocab, build_model


def test_transformer_forward_shapes():
    vocab = SimpleVocab.build([["alpha", "beta"], ["gamma"]])
    model = build_model(
        model_name="tiny", num_categories=4, vocab_size=vocab.size, max_len=8, random_init=True
    )
    input_ids = torch.tensor(
        [
            vocab.encode(["alpha", "beta"], max_len=8)[0],
            vocab.encode(["gamma"], max_len=8)[0],
        ],
        dtype=torch.long,
    )
    attention_mask = torch.tensor(
        [
            vocab.encode(["alpha", "beta"], max_len=8)[1],
            vocab.encode(["gamma"], max_len=8)[1],
        ],
        dtype=torch.long,
    )
    category_logits, risk_logit = model(input_ids=input_ids, attention_mask=attention_mask)
    assert category_logits.shape == (2, 4)
    assert risk_logit.shape == (2,)
