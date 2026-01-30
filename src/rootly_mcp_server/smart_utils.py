"""
Smart utility functions for AI-powered incident analysis.

This module provides text similarity, pattern matching, and intelligent analysis
functions for implementing smart incident management features.
"""

# Check ML library availability
import importlib.util
import logging
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

try:
    ML_AVAILABLE = (
        importlib.util.find_spec("sklearn.feature_extraction.text") is not None
        and importlib.util.find_spec("sklearn.metrics.pairwise") is not None
    )
except (ImportError, ModuleNotFoundError):
    ML_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class IncidentSimilarity:
    """Represents similarity between two incidents."""

    incident_id: str
    title: str
    similarity_score: float
    matched_services: list[str]
    matched_keywords: list[str]
    resolution_summary: str = ""
    resolution_time_hours: float | None = None


class TextSimilarityAnalyzer:
    """Analyzes text similarity between incidents using TF-IDF and cosine similarity."""

    def __init__(self):
        if not ML_AVAILABLE:
            logger.warning(
                "scikit-learn not available. Text similarity will use basic keyword matching."
            )
        self.vectorizer = None
        self.incident_vectors = None
        self.incident_metadata = {}

    def preprocess_text(self, text: str | None) -> str:
        """Clean and normalize text for analysis."""
        if not text:
            return ""

        # Convert to lowercase
        text = text.lower()

        # Remove special characters but keep spaces and important symbols
        text = re.sub(r"[^\w\s\-\.]", " ", text)

        # Replace multiple spaces with single space
        text = re.sub(r"\s+", " ", text)

        # Remove common stopwords manually (basic set)
        stopwords = {
            "the",
            "a",
            "an",
            "and",
            "or",
            "but",
            "in",
            "on",
            "at",
            "to",
            "for",
            "of",
            "with",
            "by",
            "is",
            "are",
            "was",
            "were",
        }
        words = text.split()
        text = " ".join([word for word in words if word not in stopwords and len(word) > 1])

        return text.strip()

    def extract_services(self, text: str) -> list[str]:
        """Extract service names from incident text."""
        services = []

        # Common service patterns
        service_patterns = [
            r"\b(\w+)-(?:service|api|app|server|db)\b",  # service-api, auth-service
            r"\b(\w+)(?:service|api|app|server|db)\b",  # paymentapi, authservice
            r"\b(\w+)\.(?:service|api|app|com)\b",  # auth.service, api.com
            r"\b(\w+)\s+(?:api|service|app|server|db)\b",  # payment api, auth service
        ]

        # Known service names (exact matches)
        known_services = [
            "elasticsearch",
            "elastic",
            "kibana",
            "redis",
            "postgres",
            "mysql",
            "mongodb",
            "kafka",
            "rabbitmq",
            "nginx",
            "apache",
            "docker",
            "kubernetes",
        ]

        text_lower = text.lower()

        # Extract pattern-based services
        for pattern in service_patterns:
            matches = re.findall(pattern, text_lower)
            services.extend(matches)

        # Extract known services (with word boundaries to avoid false positives)
        for service in known_services:
            if re.search(r"\b" + re.escape(service) + r"\b", text_lower):
                services.append(service)

        # Remove duplicates while preserving order
        return list(dict.fromkeys(services))

    def extract_error_patterns(self, text: str) -> list[str]:
        """Extract common error patterns from incident text."""
        patterns = []

        # HTTP status codes
        http_codes = re.findall(r"\b[45]\d\d\b", text)
        patterns.extend([f"http-{code}" for code in http_codes])

        # Database errors
        if re.search(r"\b(?:connection|timeout|database|db)\b", text.lower()):
            patterns.append("database-error")

        # Memory/resource errors
        if re.search(r"\b(?:memory|cpu|disk|resource)\b", text.lower()):
            patterns.append("resource-error")

        # Network errors
        if re.search(r"\b(?:network|dns|connection|unreachable)\b", text.lower()):
            patterns.append("network-error")

        return patterns

    def calculate_similarity(
        self, incidents: list[dict], target_incident: dict
    ) -> list[IncidentSimilarity]:
        """Calculate similarity scores between target incident and historical incidents."""
        if not incidents:
            return []

        target_text = self._combine_incident_text(target_incident)
        target_services = self.extract_services(target_text)
        target_errors = self.extract_error_patterns(target_text)

        similarities = []

        if ML_AVAILABLE and len(incidents) > 1:
            similarities = self._calculate_tfidf_similarity(
                incidents, target_incident, target_text, target_services, target_errors
            )
        else:
            similarities = self._calculate_keyword_similarity(
                incidents, target_incident, target_text, target_services, target_errors
            )

        # Sort by similarity score descending
        return sorted(similarities, key=lambda x: x.similarity_score, reverse=True)

    def _combine_incident_text(self, incident: dict) -> str:
        """Combine incident title, description, and other text fields."""
        text_parts = []

        # Get text from incident attributes (preferred)
        attributes = incident.get("attributes", {})
        title = attributes.get("title", "")
        summary = attributes.get("summary", "")
        description = attributes.get("description", "")

        # Fallback to root level if attributes are empty
        if not title:
            title = incident.get("title", "")
        if not summary:
            summary = incident.get("summary", "")
        if not description:
            description = incident.get("description", "")

        # Add non-empty parts, avoiding duplication
        for part in [title, summary, description]:
            if part and part not in text_parts:
                text_parts.append(part)

        combined = " ".join(text_parts)
        return self.preprocess_text(combined)

    def _calculate_tfidf_similarity(
        self,
        incidents: list[dict],
        target_incident: dict,
        target_text: str,
        target_services: list[str],
        target_errors: list[str],
    ) -> list[IncidentSimilarity]:
        """Use TF-IDF and cosine similarity for advanced text matching."""
        if not ML_AVAILABLE:
            return []

        # Import here to avoid issues with conditional imports
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics.pairwise import cosine_similarity

        # Prepare texts
        incident_texts = [self._combine_incident_text(inc) for inc in incidents]
        all_texts = incident_texts + [target_text]

        # Vectorize
        vectorizer = TfidfVectorizer(max_features=1000, ngram_range=(1, 2))
        tfidf_matrix = vectorizer.fit_transform(all_texts)

        # Calculate similarities
        target_vector = tfidf_matrix[-1]
        similarities = cosine_similarity(target_vector, tfidf_matrix[:-1]).flatten()

        results = []
        for i, incident in enumerate(incidents):
            if similarities[i] > 0.1:  # Only include reasonable matches
                incident_services = self.extract_services(incident_texts[i])
                incident_errors = self.extract_error_patterns(incident_texts[i])

                # Bonus for matching services and error patterns
                service_bonus = len(set(target_services) & set(incident_services)) * 0.1
                error_bonus = len(set(target_errors) & set(incident_errors)) * 0.15

                # Exact match bonus for identical preprocessed text
                exact_match_bonus = 0.0
                if (
                    target_text
                    and incident_texts[i]
                    and target_text.strip() == incident_texts[i].strip()
                ):
                    exact_match_bonus = 0.3  # Strong bonus for exact matches

                # Partial matching bonus using fuzzy keyword similarity
                partial_bonus = self._calculate_partial_similarity_bonus(
                    target_text, incident_texts[i]
                )

                final_score = min(
                    1.0,
                    similarities[i]
                    + service_bonus
                    + error_bonus
                    + exact_match_bonus
                    + partial_bonus,
                )

                results.append(
                    IncidentSimilarity(
                        incident_id=str(incident.get("id", "")),
                        title=incident.get("attributes", {}).get("title", "Unknown"),
                        similarity_score=final_score,
                        matched_services=list(set(target_services) & set(incident_services)),
                        matched_keywords=self._extract_common_keywords(
                            target_text, incident_texts[i]
                        ),
                        resolution_summary=incident.get("attributes", {}).get("summary", ""),
                        resolution_time_hours=self._calculate_resolution_time(incident),
                    )
                )

        return results

    def _calculate_keyword_similarity(
        self,
        incidents: list[dict],
        target_incident: dict,
        target_text: str,
        target_services: list[str],
        target_errors: list[str],
    ) -> list[IncidentSimilarity]:
        """Fallback keyword-based similarity when ML libraries not available."""
        target_words = set(target_text.split())

        results = []
        for incident in incidents:
            incident_text = self._combine_incident_text(incident)
            incident_words = set(incident_text.split())
            incident_services = self.extract_services(incident_text)
            incident_errors = self.extract_error_patterns(incident_text)

            # Calculate Jaccard similarity
            if len(target_words | incident_words) > 0:
                word_similarity = len(target_words & incident_words) / len(
                    target_words | incident_words
                )
            else:
                word_similarity = 0

            # Service and error pattern bonuses
            service_bonus = len(set(target_services) & set(incident_services)) * 0.2
            error_bonus = len(set(target_errors) & set(incident_errors)) * 0.25

            # Exact match bonus for identical preprocessed text
            exact_match_bonus = 0.0
            if target_text and incident_text and target_text.strip() == incident_text.strip():
                exact_match_bonus = 0.4  # Strong bonus for exact matches in keyword mode

            # Partial matching bonus using fuzzy keyword similarity
            partial_bonus = self._calculate_partial_similarity_bonus(target_text, incident_text)

            final_score = min(
                1.0,
                word_similarity + service_bonus + error_bonus + exact_match_bonus + partial_bonus,
            )

            if final_score > 0.15:  # Only include reasonable matches
                results.append(
                    IncidentSimilarity(
                        incident_id=str(incident.get("id", "")),
                        title=incident.get("attributes", {}).get("title", "Unknown"),
                        similarity_score=final_score,
                        matched_services=list(set(target_services) & set(incident_services)),
                        matched_keywords=list(target_words & incident_words)[:5],  # Top 5 matches
                        resolution_summary=incident.get("attributes", {}).get("summary", ""),
                        resolution_time_hours=self._calculate_resolution_time(incident),
                    )
                )

        return results

    def _extract_common_keywords(self, text1: str, text2: str) -> list[str]:
        """Extract common meaningful keywords between two texts with fuzzy matching."""
        words1 = set(text1.split())
        words2 = set(text2.split())

        # Exact matches
        exact_common = words1 & words2

        # Fuzzy matches for partial similarity
        fuzzy_common = []
        for word1 in words1:
            if len(word1) > 3:  # Only check longer words
                for word2 in words2:
                    if len(word2) > 3 and word1 != word2:
                        # Check if words share significant substring (fuzzy matching)
                        if self._words_similar(word1, word2):
                            fuzzy_common.append(f"{word1}~{word2}")

        # Combine exact and fuzzy matches
        all_matches = list(exact_common) + fuzzy_common
        meaningful = [word for word in all_matches if len(word.split("~")[0]) > 2]
        return meaningful[:8]  # Increased to show more matches

    def _words_similar(self, word1: str, word2: str) -> bool:
        """Check if two words are similar enough to be considered related."""
        # Handle common variations
        variations = {
            "elastic": ["elasticsearch", "elk"],
            "payment": ["payments", "pay", "billing"],
            "database": ["db", "postgres", "mysql", "mongo"],
            "timeout": ["timeouts", "timed-out", "timing-out"],
            "service": ["services", "svc", "api", "app"],
            "error": ["errors", "err", "failure", "failed", "failing"],
            "down": ["outage", "offline", "unavailable"],
        }

        # Check if words are variations of each other
        for base, variants in variations.items():
            if (word1 == base and word2 in variants) or (word2 == base and word1 in variants):
                return True
            if word1 in variants and word2 in variants:
                return True

        # Check substring similarity (at least 70% overlap for longer words)
        if len(word1) >= 5 and len(word2) >= 5:
            shorter = min(word1, word2, key=len)
            longer = max(word1, word2, key=len)
            if shorter in longer and len(shorter) / len(longer) >= 0.7:
                return True

        # Check if one word starts with the other (for prefixed services)
        if len(word1) >= 4 and len(word2) >= 4:
            if word1.startswith(word2) or word2.startswith(word1):
                return True

        return False

    def _calculate_partial_similarity_bonus(self, text1: str, text2: str) -> float:
        """Calculate bonus for partial/fuzzy keyword matches."""
        if not text1 or not text2:
            return 0.0

        words1 = set(text1.split())
        words2 = set(text2.split())

        fuzzy_matches = 0

        # Count meaningful words that could be compared
        meaningful_words1 = [w for w in words1 if len(w) > 3]
        meaningful_words2 = [w for w in words2 if len(w) > 3]

        if not meaningful_words1 or not meaningful_words2:
            return 0.0

        # Count fuzzy matches
        for word1 in meaningful_words1:
            for word2 in meaningful_words2:
                if word1 != word2 and self._words_similar(word1, word2):
                    fuzzy_matches += 1
                    break  # Only count each target word once

        # Calculate bonus based on fuzzy match ratio
        if fuzzy_matches > 0:
            # Use the smaller meaningful word set as denominator for conservative bonus
            total_possible_matches = min(len(meaningful_words1), len(meaningful_words2))
            bonus_ratio = fuzzy_matches / total_possible_matches
            return min(0.15, bonus_ratio * 0.3)  # Max 0.15 bonus for partial matches

        return 0.0

    def _calculate_resolution_time(self, incident: dict) -> float | None:
        """Calculate resolution time in hours if timestamps are available."""
        try:
            attributes = incident.get("attributes", {})
            created_at = attributes.get("created_at")
            resolved_at = attributes.get("resolved_at") or attributes.get("updated_at")

            if created_at and resolved_at:
                # Try to parse ISO format timestamps
                created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
                resolved = datetime.fromisoformat(resolved_at.replace("Z", "+00:00"))
                diff = resolved - created
                return diff.total_seconds() / 3600  # Convert to hours
        except Exception:  # nosec B110
            # Intentionally broad: invalid date formats should return None, not crash
            pass

        return None


class SolutionExtractor:
    """Extract and format solution information from resolved incidents."""

    def extract_solutions(self, similar_incidents: list[IncidentSimilarity]) -> dict[str, Any]:
        """Extract actionable solutions from similar resolved incidents."""
        if not similar_incidents:
            return {
                "solutions": [],
                "common_patterns": [],
                "average_resolution_time": None,
                "total_similar_incidents": 0,
            }

        solutions = []
        resolution_times = []
        all_keywords = []

        for incident in similar_incidents[:5]:  # Top 5 most similar
            solution_info = {
                "incident_id": incident.incident_id,
                "title": incident.title,
                "similarity": round(incident.similarity_score, 3),
                "matched_services": incident.matched_services,
                "resolution_summary": incident.resolution_summary
                or "No resolution summary available",
                "resolution_time_hours": incident.resolution_time_hours,
            }

            # Extract potential solution steps from resolution summary
            solution_steps = self._extract_action_items(incident.resolution_summary)
            if solution_steps:
                solution_info["suggested_actions"] = solution_steps

            solutions.append(solution_info)

            if incident.resolution_time_hours:
                resolution_times.append(incident.resolution_time_hours)

            all_keywords.extend(incident.matched_keywords)

        # Calculate average resolution time
        avg_resolution = sum(resolution_times) / len(resolution_times) if resolution_times else None

        # Find common patterns
        common_patterns = self._identify_common_patterns(all_keywords, similar_incidents)

        return {
            "solutions": solutions,
            "common_patterns": common_patterns,
            "average_resolution_time": round(avg_resolution, 2) if avg_resolution else None,
            "total_similar_incidents": len(similar_incidents),
        }

    def _extract_action_items(self, resolution_text: str) -> list[str]:
        """Extract potential action items from resolution text."""
        if not resolution_text:
            return []

        actions = []
        text_lower = resolution_text.lower()

        # Look for common action patterns
        action_patterns = [
            r"restart(?:ed)?\s+(\w+(?:\s+\w+)*)",
            r"clear(?:ed)?\s+(\w+(?:\s+\w+)*)",
            r"update(?:d)?\s+(\w+(?:\s+\w+)*)",
            r"fix(?:ed)?\s+(\w+(?:\s+\w+)*)",
            r"roll(?:ed)?\s+back\s+(\w+(?:\s+\w+)*)",
            r"scale(?:d)?\s+(\w+(?:\s+\w+)*)",
            r"deploy(?:ed)?\s+(\w+(?:\s+\w+)*)",
        ]

        for pattern in action_patterns:
            matches = re.findall(pattern, text_lower)
            for match in matches:
                # Extract the base action word from the pattern
                if "roll" in pattern and "back" in pattern:
                    action = f"rollback {match}".strip()
                elif "restart" in pattern:
                    action = f"restart {match}".strip()
                elif "clear" in pattern:
                    action = f"clear {match}".strip()
                elif "update" in pattern:
                    action = f"update {match}".strip()
                elif "fix" in pattern:
                    action = f"fix {match}".strip()
                elif "scale" in pattern:
                    action = f"scale {match}".strip()
                elif "deploy" in pattern:
                    action = f"deploy {match}".strip()
                else:
                    # Fallback to original logic
                    base_pattern = (
                        pattern.split("(")[0].replace("(?:ed)?", "").replace("(?:d)?", "")
                    )
                    # Extract replacement outside f-string for Python 3.10 compatibility
                    cleaned_pattern = base_pattern.replace(r"\s+", " ")
                    action = f"{cleaned_pattern} {match}".strip()
                actions.append(action)

        # Look for explicit steps
        if "step" in text_lower or "action" in text_lower:
            sentences = resolution_text.split(".")
            for sentence in sentences:
                if any(word in sentence.lower() for word in ["step", "action", "fix", "solution"]):
                    actions.append(sentence.strip())

        return actions[:5]  # Limit to top 5 actions

    def _identify_common_patterns(
        self, keywords: list[str], incidents: list[IncidentSimilarity]
    ) -> list[str]:
        """Identify common patterns across similar incidents."""
        patterns = []

        # Service patterns
        all_services = []
        for incident in incidents:
            all_services.extend(incident.matched_services)

        if all_services:
            common_services = [
                service for service in set(all_services) if all_services.count(service) >= 2
            ]
            if common_services:
                patterns.append(f"Common services affected: {', '.join(common_services)}")

        # Keyword patterns
        if keywords:
            keyword_counts = {}
            for keyword in keywords:
                keyword_counts[keyword] = keyword_counts.get(keyword, 0) + 1

            frequent_keywords = [k for k, v in keyword_counts.items() if v >= 2 and len(k) > 3]
            if frequent_keywords:
                patterns.append(f"Common keywords: {', '.join(frequent_keywords[:3])}")

        # Resolution time patterns
        resolution_times = [
            inc.resolution_time_hours for inc in incidents if inc.resolution_time_hours is not None
        ]
        if resolution_times:
            avg_time = sum(resolution_times) / len(resolution_times)
            if avg_time < 1:
                patterns.append("These incidents typically resolve quickly (< 1 hour)")
            elif avg_time > 4:
                patterns.append("These incidents typically take longer to resolve (> 4 hours)")
            else:
                patterns.append(f"These incidents typically resolve in {avg_time:.1f} hours")

        return patterns
