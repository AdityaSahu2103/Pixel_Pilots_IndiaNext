"""
CyberShield AI - Adversarial Testing Service
Tests detection robustness by mutating inputs and rescanning.
"""
import re
import random
from backend.models.schemas import (
    AdversarialResult, MutationResult, ExtractedContent, SourceType
)


# Unicode confusable characters
CONFUSABLES = {
    'a': ['а', 'ⓐ', 'ạ'],  # Cyrillic а, etc.
    'e': ['е', 'ⓔ', 'ẹ'],
    'o': ['о', 'ⓞ', 'ọ'],
    'i': ['і', 'ⓘ', 'ị'],
    'l': ['ⅼ', 'ⓛ', 'ḷ'],
    's': ['ꜱ', 'ⓢ', 'ṣ'],
    'c': ['ϲ', 'ⓒ', 'ç'],
}


class AdversarialTester:
    """
    Tests detection pipeline robustness through:
    1. Character substitution (homoglyph attacks)
    2. Whitespace/unicode injection
    3. Content rephrasing
    4. Encoding tricks
    """

    MUTATION_STRATEGIES = [
        "homoglyph_substitution",
        "zero_width_injection",
        "case_alternation",
        "whitespace_padding",
        "url_encoding",
        "word_splitting",
    ]

    async def test(
        self,
        original_content: str,
        original_detected: bool,
        scan_func,  # Async callable that rescans content
    ) -> AdversarialResult:
        """Run adversarial mutations and rescan."""
        mutations = []

        for strategy in self.MUTATION_STRATEGIES:
            mutated = self._apply_mutation(original_content, strategy)
            if mutated == original_content:
                continue

            # Rescan mutated content
            try:
                extracted = ExtractedContent(
                    source_type=SourceType.TEXT,
                    plain_text=mutated,
                    urls=re.findall(r'https?://[^\s]+', mutated)
                )
                rescan_result = await scan_func(extracted)
                mutated_detected = any(d.detected for d in rescan_result)
            except Exception:
                mutated_detected = False

            evasion = original_detected and not mutated_detected

            mutations.append(MutationResult(
                mutation_type=strategy,
                mutated_input=mutated[:200],  # Truncate for response
                original_detected=original_detected,
                mutated_detected=mutated_detected,
                evasion_successful=evasion
            ))

        # Calculate robustness
        total = len(mutations)
        evasions = sum(1 for m in mutations if m.evasion_successful)
        caught = total - evasions

        robustness = (caught / total * 100) if total > 0 else 100.0

        return AdversarialResult(
            total_mutations=total,
            evasions_caught=caught,
            evasions_missed=evasions,
            robustness_score=round(robustness, 2),
            mutations=mutations
        )

    def _apply_mutation(self, text: str, strategy: str) -> str:
        """Apply a specific mutation strategy."""
        if strategy == "homoglyph_substitution":
            return self._homoglyph_sub(text)
        elif strategy == "zero_width_injection":
            return self._zero_width_inject(text)
        elif strategy == "case_alternation":
            return self._case_alternate(text)
        elif strategy == "whitespace_padding":
            return self._whitespace_pad(text)
        elif strategy == "url_encoding":
            return self._url_encode_partial(text)
        elif strategy == "word_splitting":
            return self._word_split(text)
        return text

    def _homoglyph_sub(self, text: str) -> str:
        """Replace random chars with visually identical unicode."""
        result = list(text)
        for i, char in enumerate(result):
            if char.lower() in CONFUSABLES and random.random() < 0.3:
                result[i] = random.choice(CONFUSABLES[char.lower()])
        return "".join(result)

    def _zero_width_inject(self, text: str) -> str:
        """Inject zero-width characters."""
        zwc = '\u200b'  # Zero-width space
        words = text.split()
        result = []
        for word in words:
            if len(word) > 4 and random.random() < 0.3:
                mid = len(word) // 2
                word = word[:mid] + zwc + word[mid:]
            result.append(word)
        return " ".join(result)

    def _case_alternate(self, text: str) -> str:
        """aLtErNaTe CaSe."""
        return "".join(
            c.upper() if i % 2 else c.lower()
            for i, c in enumerate(text)
        )

    def _whitespace_pad(self, text: str) -> str:
        """Add extra whitespace between words."""
        return re.sub(r'\s+', '  \t  ', text)

    def _url_encode_partial(self, text: str) -> str:
        """Partially URL-encode characters."""
        result = []
        for char in text:
            if char.isalpha() and random.random() < 0.15:
                result.append(f"%{ord(char):02X}")
            else:
                result.append(char)
        return "".join(result)

    def _word_split(self, text: str) -> str:
        """Split words with invisible separators."""
        words = text.split()
        result = []
        for word in words:
            if len(word) > 5 and random.random() < 0.3:
                mid = len(word) // 2
                result.append(word[:mid] + "\u00AD" + word[mid:])
            else:
                result.append(word)
        return " ".join(result)
