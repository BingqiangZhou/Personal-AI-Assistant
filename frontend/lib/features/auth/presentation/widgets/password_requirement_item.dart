import 'package:flutter/material.dart';

class PasswordRequirementItem extends StatelessWidget {
  final String text;
  final bool isValid;

  const PasswordRequirementItem({
    super.key,
    required this.text,
    required this.isValid,
  });

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Row(
        children: [
          Icon(
            isValid ? Icons.check_circle : Icons.radio_button_unchecked,
            size: 16,
            color: isValid
                ? Colors.green
                : Theme.of(context).colorScheme.onSurfaceVariant.withOpacity(0.6),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              text,
              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                color: isValid
                    ? Colors.green
                    : Theme.of(context).colorScheme.onSurfaceVariant,
                fontWeight: isValid ? FontWeight.w500 : FontWeight.normal,
              ),
            ),
          ),
        ],
      ),
    );
  }
}