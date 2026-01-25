"""
Unit tests for utility functions.
工具函数单元测试
"""

from app.core.utils import filter_thinking_content


class TestFilterThinkingContent:
    """Test suite for filter_thinking_content function / filter_thinking_content 函数测试套件"""

    def test_filter_thinking_content_standard(self):
        """Test standard thinking tag filtering / 测试标准 thinking 标签过滤"""
        input_text = "<thinking>Let me think about this</thinking>Hello, world!"
        expected = "Hello, world!"
        assert filter_thinking_content(input_text) == expected

    def test_filter_thinking_content_multiline(self):
        """Test multiline thinking content / 测试多行 thinking 内容"""
        input_text = """<thinking>
    This is a multiline
    thinking process
    with several lines
    </thinking>
    The actual answer is here."""
        expected = "The actual answer is here."
        assert filter_thinking_content(input_text) == expected

    def test_filter_thinking_content_multiple(self):
        """Test multiple thinking tags / 测试多段 thinking 标签"""
        input_text = "<thinking>First thought</thinking>Part 1<thinking>Second thought</thinking>Part 2"
        expected = "Part 1Part 2"
        assert filter_thinking_content(input_text) == expected

    def test_filter_thinking_content_none(self):
        """Test when no thinking tag is present / 测试无 thinking 标签时原样返回"""
        input_text = "Just a normal response without thinking tags."
        expected = input_text
        assert filter_thinking_content(input_text) == expected

    def test_filter_thinking_content_pure_thinking(self):
        """Test when content is only thinking tags / 测试纯 thinking 内容"""
        input_text = "<thinking>This is only thinking</thinking>"
        expected = ""
        assert filter_thinking_content(input_text) == expected

    def test_filter_thinking_content_case_insensitive(self):
        """Test case insensitivity / 测试大小写不敏感"""
        input_text = "<THINKING>Upper case tag</THINKING>The content"
        expected = "The content"
        assert filter_thinking_content(input_text) == expected

    def test_filter_thinking_content_mixed_case(self):
        """Test mixed case tags / 测试混合大小写标签"""
        input_text = "<Thinking>Mixed case</Thinking>Content here"
        expected = "Content here"
        assert filter_thinking_content(input_text) == expected

    def test_filter_thinking_content_empty_string(self):
        """Test empty string / 测试空字符串"""
        assert filter_thinking_content("") == ""

    def test_filter_thinking_content_none_input(self):
        """Test None input / 测试 None 输入"""
        assert filter_thinking_content(None) == None

    def test_filter_thinking_content_preserves_whitespace(self):
        """Test that internal whitespace and newlines are preserved / 测试内部空白和换行被保留"""
        input_text = "<thinking>Thoughts</thinking>\nLine 1\n\nLine 2"
        expected = "Line 1\n\nLine 2"
        assert filter_thinking_content(input_text) == expected

    def test_filter_thinking_content_preserves_chinese_punctuation(self):
        """Test that normal Chinese punctuation is NOT filtered / 测试正常的中文标点不被过滤"""
        input_text = "这是一个测试、包含逗号。还有句号。"
        assert filter_thinking_content(input_text) == input_text

    def test_filter_thinking_content_complex_response(self):
        """Test realistic AI response format preserving structure / 测试真实 AI 响应并保留结构"""
        input_text = """<thinking>
Let me analyze this question.
</thinking>

Based on my analysis:
1. Item one
2. Item two

Conclusion."""
        expected = """Based on my analysis:
1. Item one
2. Item two

Conclusion."""
        assert filter_thinking_content(input_text) == expected.strip()

    def test_filter_thinking_content_nested_content(self):
        """Test thinking content with special characters / 测试包含特殊字符的 thinking 内容"""
        input_text = "<thinking>This has <special> characters & symbols</thinking>Normal text"
        expected = "Normal text"
        assert filter_thinking_content(input_text) == expected

    # === <think> tag tests / <think> 标签测试 ===

    def test_filter_thinking_content_think_tag(self):
        """Test <think> tag filtering / 测试 <think> 标签过滤"""
        input_text = "<think>Let me think about this</think>The answer"
        expected = "The answer"
        assert filter_thinking_content(input_text) == expected

    def test_filter_thinking_content_think_tag_multiline(self):
        """Test multiline <think> content / 测试多行 <think> 内容"""
        input_text = """<think>
    This is a multiline
    thinking process
    with several lines
</think>
The actual answer is here."""
        expected = "The actual answer is here."
        assert filter_thinking_content(input_text) == expected

    def test_filter_thinking_content_think_tag_multiple(self):
        """Test multiple <think> tags / 测试多段 <think> 标签"""
        input_text = "<think>First thought</think>Part 1<think>Second thought</think>Part 2"
        expected = "Part 1Part 2"
        assert filter_thinking_content(input_text) == expected

    def test_filter_thinking_content_think_tag_pure(self):
        """Test when content is only <think> tags / 测试纯 <think> 内容"""
        input_text = "<think>This is only thinking</think>"
        expected = ""
        assert filter_thinking_content(input_text) == expected

    def test_filter_thinking_content_think_tag_case_insensitive(self):
        """Test <think> tag case insensitivity / 测试 <think> 标签大小写不敏感"""
        input_text = "<THINK>Upper case tag</THINK>The content"
        expected = "The content"
        assert filter_thinking_content(input_text) == expected

    # === Mixed tag tests / 混合标签测试 ===

    def test_filter_thinking_content_mixed_tags(self):
        """Test both <thinking> and <think> tags / 测试混合两种标签"""
        input_text = "<thinking>First thought</thinking>Part 1<think>Second thought</think>Part 2"
        expected = "Part 1Part 2"
        assert filter_thinking_content(input_text) == expected

    def test_filter_thinking_content_mixed_order(self):
        """Test different order of tags / 测试标签顺序"""
        input_text = "<think>First</think>Part 1<thinking>Second thought</thinking>Part 2"
        expected = "Part 1Part 2"
        assert filter_thinking_content(input_text) == expected
