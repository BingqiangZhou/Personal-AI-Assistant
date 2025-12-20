#!/bin/bash

# 工作流程违规处理脚本
# 当检测到流程违规时自动执行

set -e

# 颜色定义
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# 日志函数
log_error() {
    echo -e "${RED}❌ ERROR: $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  WARNING: $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ SUCCESS: $1${NC}"
}

log_info() {
    echo -e "ℹ️  INFO: $1"
}

# 检查函数
check_prd_exists() {
    local feature_name="$1"
    local prd_path="specs/active/${feature_name}.md"

    if [ ! -f "$prd_path" ]; then
        log_error "PRD文档不存在: $prd_path"
        return 1
    fi

    log_success "PRD文档存在: $prd_path"
    return 0
}

check_pm_involvement() {
    local task_log="$1"

    if [ -f "$task_log" ] && grep -q "product-manager" "$task_log"; then
        log_success "产品经理已参与任务"
        return 0
    else
        log_error "产品经理未参与任务"
        return 1
    fi
}

check_verification_reports() {
    local feature_name="$1"
    local verification_path="docs/verification/${feature_name}-verification-report.md"
    local completion_path="docs/completion/${feature_name}-completion-report.md"

    local missing_reports=()

    if [ ! -f "$verification_path" ]; then
        missing_reports+=("验证报告")
    fi

    if [ ! -f "$completion_path" ]; then
        missing_reports+=("完成报告")
    fi

    if [ ${#missing_reports[@]} -gt 0 ]; then
        log_error "缺少报告: ${missing_reports[*]}"
        return 1
    fi

    log_success "所有必需报告都存在"
    return 0
}

check_prd_status() {
    local feature_name="$1"
    local completed_path="specs/completed/${feature_name}.md"

    if [ -f "$completed_path" ]; then
        log_success "PRD已移至completed目录"
        return 0
    else
        log_error "PRD未移至completed目录"
        return 1
    fi
}

# 违规处理函数
handle_violation() {
    local violation_type="$1"
    local feature_name="$2"

    log_warning "检测到流程违规: $violation_type"
    log_warning "功能名称: $feature_name"

    case "$violation_type" in
        "missing_prd")
            log_info "处理措施：停止开发，要求产品经理创建PRD"
            echo "STOP: 立即停止开发工作"
            echo "ACTION: 产品经理必须先创建PRD文档"
            echo "LOCATION: specs/active/${feature_name}.md"
            ;;
        "missing_pm")
            log_info "处理措施：暂停任务，要求产品经理参与"
            echo "STOP: 暂停当前任务"
            echo "ACTION: 必须让产品经理分析需求"
            echo "REASON: 产品经理必须是第一个分析用户需求的"
            ;;
        "missing_validation")
            log_info "处理措施：暂停完成，要求产品经理验收"
            echo "STOP: 暂停标记任务完成"
            echo "ACTION: 产品经理必须进行最终验收"
            echo "REQUIREMENTS: 创建验证报告和完成报告"
            ;;
        "missing_document_update")
            log_info "处理措施：更新文档状态"
            echo "ACTION: 更新PRD状态并移至completed目录"
            echo "REQUIREMENTS: 创建所有必需的报告文档"
            ;;
        *)
            log_error "未知违规类型: $violation_type"
            ;;
    esac

    return 1
}

# 完整流程验证
validate_complete_workflow() {
    local feature_name="$1"
    local violations=()

    log_info "开始验证完整工作流程: $feature_name"

    # 检查1: PRD文档是否存在
    if ! check_prd_exists "$feature_name"; then
        violations+=("missing_prd")
    fi

    # 检查2: 验证报告是否存在
    if ! check_verification_reports "$feature_name"; then
        violations+=("missing_validation")
    fi

    # 检查3: PRD状态是否正确
    if ! check_prd_status "$feature_name"; then
        violations+=("missing_document_update")
    fi

    # 处理违规
    if [ ${#violations[@]} -gt 0 ]; then
        for violation in "${violations[@]}"; do
            handle_violation "$violation" "$feature_name"
        done
        return 1
    fi

    log_success "工作流程验证通过！"
    return 0
}

# 使用说明
show_usage() {
    echo "使用方法: $0 [选项] <feature_name>"
    echo ""
    echo "选项:"
    echo "  -c, --check    检查完整工作流程"
    echo "  -p, --prd      检查PRD文档"
    echo "  -v, --verify   检查验证报告"
    echo "  -s, --status   检查PRD状态"
    echo "  -h, --help     显示帮助信息"
    echo ""
    echo "示例:"
    echo "  $0 --check podcast-information-feed"
    echo "  $0 --prd user-timezone-setting"
}

# 主函数
main() {
    case "$1" in
        -c|--check)
            if [ -z "$2" ]; then
                log_error "请提供功能名称"
                show_usage
                exit 1
            fi
            validate_complete_workflow "$2"
            ;;
        -p|--prd)
            if [ -z "$2" ]; then
                log_error "请提供功能名称"
                show_usage
                exit 1
            fi
            check_prd_exists "$2"
            ;;
        -v|--verify)
            if [ -z "$2" ]; then
                log_error "请提供功能名称"
                show_usage
                exit 1
            fi
            check_verification_reports "$2"
            ;;
        -s|--status)
            if [ -z "$2" ]; then
                log_error "请提供功能名称"
                show_usage
                exit 1
            fi
            check_prd_status "$2"
            ;;
        -h|--help)
            show_usage
            ;;
        *)
            log_error "未知选项: $1"
            show_usage
            exit 1
            ;;
    esac
}

# 脚本入口
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi