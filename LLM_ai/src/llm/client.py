"""Claude API 客户端封装"""

from __future__ import annotations

import os
from typing import Any

import anthropic


class LLMClient:
    """Claude API 客户端，支持 retry 和 token 计数"""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "claude-sonnet-4-20250514",
        max_tokens: int = 4096,
        temperature: float = 0.3,
    ):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self._client: anthropic.Anthropic | None = None
        self.total_input_tokens = 0
        self.total_output_tokens = 0

    @property
    def client(self) -> anthropic.Anthropic:
        if self._client is None:
            if not self.api_key:
                raise ValueError(
                    "未设置 ANTHROPIC_API_KEY 环境变量，"
                    "请设置后重试: export ANTHROPIC_API_KEY=sk-ant-..."
                )
            self._client = anthropic.Anthropic(api_key=self.api_key)
        return self._client

    def generate(
        self,
        prompt: str,
        system: str = "",
        max_tokens: int | None = None,
        temperature: float | None = None,
    ) -> str:
        """调用 Claude API 生成文本"""
        messages = [{"role": "user", "content": prompt}]
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens or self.max_tokens,
            "temperature": temperature if temperature is not None else self.temperature,
            "messages": messages,
        }
        if system:
            kwargs["system"] = system

        response = self.client.messages.create(**kwargs)

        # 统计 token
        self.total_input_tokens += response.usage.input_tokens
        self.total_output_tokens += response.usage.output_tokens

        # 提取文本
        result = ""
        for block in response.content:
            if block.type == "text":
                result += block.text
        return result

    def generate_with_cache(
        self,
        prompt: str,
        system: str = "",
        cache_control: dict | None = None,
    ) -> str:
        """带 prompt caching 的生成（用于长报告上下文）"""
        messages = [{"role": "user", "content": prompt}]

        system_blocks = []
        if system:
            block: dict[str, Any] = {"type": "text", "text": system}
            if cache_control:
                block["cache_control"] = cache_control
            system_blocks.append(block)

        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "messages": messages,
        }
        if system_blocks:
            kwargs["system"] = system_blocks

        response = self.client.messages.create(**kwargs)

        self.total_input_tokens += response.usage.input_tokens
        self.total_output_tokens += response.usage.output_tokens

        result = ""
        for block in response.content:
            if block.type == "text":
                result += block.text
        return result

    @property
    def token_stats(self) -> dict[str, int]:
        return {
            "input_tokens": self.total_input_tokens,
            "output_tokens": self.total_output_tokens,
            "total_tokens": self.total_input_tokens + self.total_output_tokens,
        }
