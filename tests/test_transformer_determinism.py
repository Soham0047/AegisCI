import torch

from ml.models.transformer import SimpleVocab, build_model


def test_transformer_determinism():
    torch.manual_seed(1234)
    torch.use_deterministic_algorithms(True)

    vocab = SimpleVocab.build([["alpha", "beta"]])
    input_ids = torch.tensor([vocab.encode(["alpha", "beta"], max_len=8)[0]], dtype=torch.long)
    attention_mask = torch.tensor([vocab.encode(["alpha", "beta"], max_len=8)[1]], dtype=torch.long)

    model = build_model(
        model_name="tiny", num_categories=3, vocab_size=vocab.size, max_len=8, random_init=True
    )
    model.eval()
    first = model(input_ids=input_ids, attention_mask=attention_mask)
    second = model(input_ids=input_ids, attention_mask=attention_mask)

    assert torch.allclose(first[0], second[0], atol=1e-6)
    assert torch.allclose(first[1], second[1], atol=1e-6)
