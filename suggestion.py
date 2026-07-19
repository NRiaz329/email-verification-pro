from typing import List
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
import jellyfish
import numpy as np


class TrieNode:
    def __init__(self, char: str):
        self.char = char
        self.children = {}
        self.word_end = False


class Trie:
    def __init__(self):
        self.root = TrieNode('')

    def add(self, word: str):
        node = self.root
        for char in word:
            if char not in node.children:
                node.children[char] = TrieNode(char)
            node = node.children[char]
        node.word_end = True

    def search(self, word: str) -> bool:
        node = self.root
        for char in word:
            if char not in node.children:
                return False
            node = node.children[char]
        return node.word_end


@lru_cache(maxsize=1)
def _build_trie(valid_domains_tuple):
    trie = Trie()
    for valid_domain in valid_domains_tuple:
        trie.add(valid_domain)
    return trie


def suggest_email_domain(domain: str, valid_domains: List[str]) -> List[str]:
    """Suggest likely-intended domains for a typo'd domain.

    Note: the trie is now built once (cached) instead of on every call --
    the original rebuilt it from scratch for every single email checked,
    which is wasted work when the valid-domain list never changes.
    """
    if not domain:
        return []

    valid_domains_tuple = tuple(valid_domains)
    trie = _build_trie(valid_domains_tuple)

    # Calculate distances using a fast string distance metric
    distances = {}
    workers = int(np.minimum(16, max(1, len(valid_domains))))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        for valid_domain, distance in zip(
            valid_domains,
            executor.map(lambda x: jellyfish.damerau_levenshtein_distance(domain, x), valid_domains),
        ):
            if distance <= 2:
                distances.setdefault(distance, [])
                if valid_domain not in distances[distance]:
                    distances[distance].append(valid_domain)

    sorted_domains = []
    if distances:
        min_distance = min(distances.keys())
        sorted_domains = sorted(distances[min_distance])
        sorted_domains = [d for d in sorted_domains if trie.search(d)]

    # Check for phonetic similarity using Soundex
    soundex_domain = jellyfish.soundex(domain)
    phonetically_similar_domains = [
        d for d in valid_domains
        if jellyfish.soundex(d) == soundex_domain and d not in sorted_domains
    ]

    return sorted_domains + phonetically_similar_domains
