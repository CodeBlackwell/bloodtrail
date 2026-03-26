# BloodTrail Wizard Demo

## Quick Test

```bash
# Run all wizard tests
pytest tests/tools/post/bloodtrail/wizard/ -v

# Expected: 54 tests passing
```

## Manual Testing (Simulated)

Since we don't have a live AD target, here's how to verify the wizard flow with mocks:

### Test 1: Progress Display

```python
# Create a simple test script: test_wizard_manual.py
from tools.post.bloodtrail.wizard.flow import WizardFlow
from tools.post.bloodtrail.wizard.steps import StepResult
from unittest.mock import patch

@patch("tools.post.bloodtrail.wizard.steps.DetectStep.run")
@patch("tools.post.bloodtrail.wizard.steps.ChooseModeStep.run")
def test_display(mock_choose, mock_detect):
    mock_detect.return_value = StepResult(True, "choose_mode", "Detected services", {})
    mock_choose.return_value = StepResult(True, "done", "Selected auto", {})

    flow = WizardFlow(target="10.10.10.182", resume=False)
    flow.run()
```

Expected output:
```
[Step 1/5] Target Detection
  → Detected services

[Step 2/5] Choose Enumeration Mode
  → Selected auto

┌──────────────────────────────────────────────────────────────────────┐
│ Wizard Complete                                                      │
└──────────────────────────────────────────────────────────────────────┘

Summary:
  Completed steps: 2
  Findings discovered: 0
  Credentials found: 0

  ✓ All steps completed successfully

Completed:
  ✓ Target Detection
  ✓ Choose Enumeration Mode
```

### Test 2: Interrupt Handling

```python
@patch("tools.post.bloodtrail.wizard.steps.DetectStep.run")
def test_interrupt(mock_detect):
    mock_detect.side_effect = KeyboardInterrupt()

    flow = WizardFlow(target="10.10.10.182", resume=False)

    try:
        flow.run()
    except KeyboardInterrupt:
        pass  # Expected
```

Expected output:
```
[Step 1/5] Target Detection

[!] Interrupted - saving progress...

Resume with: crack bloodtrail --wizard-resume 10.10.10.182
```

### Test 3: Resume

```python
from tools.post.bloodtrail.wizard.state import WizardState

# Create a checkpoint
state = WizardState(target="10.10.10.182")
state.completed_steps = ["detect"]
state.current_step = "choose_mode"
state.save("10.10.10.182")

# Resume
flow = WizardFlow(target="10.10.10.182", resume=True)
# Should print: [*] Resuming from step: choose_mode
```

## CLI Integration Test

```bash
# With actual CLI (requires bloodtrail CLI setup)
crack bloodtrail --wizard 10.10.10.182

# Or with resume
crack bloodtrail --wizard-resume 10.10.10.182
```

## Visual Features Implemented

### 1. Step Counter
- Format: `[Step X/5] Step Title`
- Color: Cyan for counter, Bold for title
- Updates dynamically as flow progresses

### 2. Progress Messages
- Success: Green arrow `→`
- Error: Red `[!]`
- Warning: Yellow `[!]`

### 3. Summary Box
```
┌──────────────────────────────────────────────────────────────────────┐
│ Wizard Complete                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### 4. Completed Steps List
```
Completed:
  ✓ Target Detection
  ✓ Choose Enumeration Mode
  ✓ Enumeration
  ✓ Analysis
  ✓ Recommendations
```

### 5. Resume Instructions
```
Resume with: crack bloodtrail --wizard-resume <target>
```

## Test Coverage

| Phase | Tests | Status |
|-------|-------|--------|
| Phase 1 (State) | 9 | ✓ All passing |
| Phase 2 (Steps) | 7 | ✓ All passing |
| Phase 3 (Flow) | 10 | ✓ All passing |
| Phase 4 (Enumerate) | 6 | ✓ All passing |
| Phase 5 (Recommend) | 8 | ✓ All passing |
| Phase 6 (CLI) | 8 | ✓ All passing |
| Phase 7 (Polish) | 6 | ✓ All passing |
| **Total** | **54** | **✓ All passing** |

## No Regressions

```bash
# All BloodTrail tests
pytest tests/tools/post/bloodtrail/ -v

# Expected: 851 tests passing
```

## What Phase 7 Added

1. **Progress Tracking**
   - Step counter `[Step X/5]`
   - Total steps calculated dynamically
   - Color-coded headers

2. **Interrupt Handling**
   - Catches `KeyboardInterrupt`
   - Saves checkpoint before exit
   - Prints resume command
   - Re-raises for CLI handling

3. **Summary Display**
   - Green box header
   - Completed steps count
   - Findings/credentials count
   - Success/warning indicator
   - List of completed steps with checkmarks

4. **Integration Tests**
   - End-to-end mock flow (5 steps)
   - Progress indicator validation
   - Interrupt handling verification
   - Checkpoint save on interrupt
   - Summary display validation
   - Resume message format check

## Success Metrics

- ✓ All 6 Phase 7 tests passing
- ✓ All 54 wizard tests passing
- ✓ All 851 BloodTrail tests passing (no regressions)
- ✓ Clean interrupt handling
- ✓ Professional display output
- ✓ Resume capability working
- ✓ TDD approach followed (tests written first)
