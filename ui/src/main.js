// USB Writer by Kognit Labs - Frontend JavaScript (Wizard Style)

// Tauri v2 imports
import { open } from '@tauri-apps/plugin-dialog';
import { invoke } from '@tauri-apps/api/core';

// State
let currentStep = 1;
let selectedIso = null;
let selectedDrive = null;
let isWriting = false;
let progressInterval = null;
let selectedWriteMode = null;  // Will be auto-detected based on ISO type

// DOM Elements - will be initialized after DOM loads
let elements = {};

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  initializeElements();
  initializeApp();
});

function initializeElements() {
  elements = {
    // Step indicators
    stepDots: document.querySelectorAll('.step-dot'),

    // Step 1 - ISO
    isoDropZone: document.getElementById('iso-drop-zone'),
    isoSelector: document.getElementById('iso-selector'),
    isoInfo: document.getElementById('iso-info'),
    isoName: document.getElementById('iso-name'),
    isoSize: document.getElementById('iso-size'),
    isoVersion: document.getElementById('iso-version'),
    isoRemove: document.getElementById('iso-remove'),
    btnNext1: document.getElementById('btn-next-1'),

    // Step 2 - USB
    driveList: document.getElementById('drive-list'),
    refreshDrives: document.getElementById('refresh-drives'),
    btnBack2: document.getElementById('btn-back-2'),
    btnNext2: document.getElementById('btn-next-2'),

    // Step 3 - Write
    summaryIso: document.getElementById('summary-iso'),
    summaryUsb: document.getElementById('summary-usb'),
    summarySection: document.getElementById('summary-section'),
    optionsSection: document.querySelector('.options-section'),
    progressSection: document.getElementById('progress-section'),
    progressStage: document.getElementById('progress-stage'),
    progressPercent: document.getElementById('progress-percent'),
    progressBar: document.getElementById('progress-bar'),
    currentFile: document.getElementById('current-file'),
    writeSpeed: document.getElementById('write-speed'),
    writeEta: document.getElementById('write-eta'),
    successMessage: document.getElementById('success-message'),
    errorMessage: document.getElementById('error-message'),
    errorText: document.getElementById('error-text'),
    btnBack3: document.getElementById('btn-back-3'),
    btnWrite: document.getElementById('btn-write'),
    btnCancel: document.getElementById('btn-cancel'),
    btnDone: document.getElementById('btn-done'),
  };
}

async function initializeApp() {
  console.log('USB Writer by Kognit Labs - Initializing...');
  console.log('Tauri available:', typeof window.__TAURI__ !== 'undefined');

  setupIsoSelector();
  setupDriveRefresh();
  setupNavigation();
  setupWriteButton();

  // Initial drive scan
  await refreshDriveList();

  console.log('Initialization complete');
}

// =================================================================
// Navigation
// =================================================================

function setupNavigation() {
  // Step 1 -> Step 2
  elements.btnNext1.addEventListener('click', () => goToStep(2));

  // Step 2 -> Step 1
  elements.btnBack2.addEventListener('click', () => goToStep(1));

  // Step 2 -> Step 3
  elements.btnNext2.addEventListener('click', () => {
    updateSummary();
    goToStep(3);
  });

  // Step 3 -> Step 2
  elements.btnBack3.addEventListener('click', () => goToStep(2));

  // Done button - reset to step 1
  elements.btnDone.addEventListener('click', () => {
    resetAll();
    goToStep(1);
  });
}

function goToStep(step) {
  // Hide all steps
  document.querySelectorAll('.wizard-step').forEach(s => s.classList.remove('active'));

  // Show target step
  document.getElementById(`step-${step}`).classList.add('active');

  // Update step indicators
  elements.stepDots.forEach(dot => {
    const dotStep = parseInt(dot.dataset.step);
    dot.classList.remove('active', 'completed');
    if (dotStep === step) {
      dot.classList.add('active');
    } else if (dotStep < step) {
      dot.classList.add('completed');
    }
  });

  currentStep = step;

  // Refresh drives when entering step 2
  if (step === 2) {
    refreshDriveList();
  }
}

function updateSummary() {
  if (selectedIso) {
    elements.summaryIso.textContent = selectedIso.name;
  }
  if (selectedDrive) {
    elements.summaryUsb.textContent = `${selectedDrive.name} (${selectedDrive.size_formatted})`;
  }
}

function resetAll() {
  selectedIso = null;
  selectedDrive = null;
  isWriting = false;

  // Reset ISO section
  elements.isoSelector.classList.remove('hidden');
  elements.isoInfo.classList.add('hidden');
  elements.btnNext1.disabled = true;

  // Reset USB section
  elements.btnNext2.disabled = true;

  // Reset Step 3
  elements.summarySection.classList.remove('hidden');
  elements.optionsSection.classList.remove('hidden');
  elements.progressSection.classList.add('hidden');
  elements.successMessage.classList.add('hidden');
  elements.errorMessage.classList.add('hidden');
  elements.btnBack3.classList.remove('hidden');
  elements.btnWrite.classList.remove('hidden');
  elements.btnCancel.classList.add('hidden');
  elements.btnDone.classList.add('hidden');
}

// =================================================================
// ISO Selection
// =================================================================

function setupIsoSelector() {
  // Click to browse
  elements.isoDropZone.addEventListener('click', async (e) => {
    e.preventDefault();
    e.stopPropagation();
    console.log('Drop zone clicked, opening file dialog...');
    await selectIsoFile();
  });

  // Drag and drop - use Tauri's drag-drop event
  // For webview drag-drop, we need to handle it differently
  elements.isoDropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    e.stopPropagation();
    elements.isoDropZone.classList.add('dragover');
  });

  elements.isoDropZone.addEventListener('dragleave', (e) => {
    e.preventDefault();
    e.stopPropagation();
    elements.isoDropZone.classList.remove('dragover');
  });

  elements.isoDropZone.addEventListener('drop', async (e) => {
    e.preventDefault();
    e.stopPropagation();
    elements.isoDropZone.classList.remove('dragover');
    console.log('Drop event received');

    // Try to get file path from dataTransfer
    const files = e.dataTransfer.files;
    if (files && files.length > 0) {
      const file = files[0];
      console.log('Dropped file:', file.name, file.path);

      // In Tauri, we might get the path directly or need to use the file name
      if (file.path) {
        if (file.name.toLowerCase().endsWith('.iso')) {
          await loadIsoInfo(file.path);
        } else {
          alert('Please select a valid ISO file');
        }
      } else {
        // Fallback: open file dialog
        console.log('No path available from drop, opening dialog...');
        await selectIsoFile();
      }
    }
  });

  // Remove button
  elements.isoRemove.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    clearIsoSelection();
  });
}

async function selectIsoFile() {
  try {
    console.log('Opening file dialog...');

    // Use imported open function from @tauri-apps/plugin-dialog
    const selected = await open({
      multiple: false,
      directory: false,
      filters: [{
        name: 'ISO Files',
        extensions: ['iso', 'ISO']
      }],
      title: 'Select ISO File'
    });

    console.log('Dialog result:', selected);

    if (selected) {
      await loadIsoInfo(selected);
    }
  } catch (error) {
    console.error('Error selecting file:', error);
    alert('Failed to open file dialog: ' + error);
  }
}

async function loadIsoInfo(path) {
  try {
    console.log('Loading ISO info for:', path);

    // Use imported invoke function from @tauri-apps/api/core
    const info = await invoke('get_iso_info', { path: path });

    console.log('ISO info received:', info);

    if (!info.is_valid) {
      alert('Invalid ISO file. Please select a valid ISO file.');
      return;
    }

    selectedIso = info;

    // Set recommended write mode from backend detection
    selectedWriteMode = getWriteModeString(info.recommended_mode);
    console.log('Detected ISO type:', info.iso_type, 'Recommended mode:', selectedWriteMode);

    // Update UI
    elements.isoSelector.classList.add('hidden');
    elements.isoInfo.classList.remove('hidden');

    elements.isoName.textContent = info.name;
    elements.isoSize.textContent = info.size_formatted;

    // Use detected version from backend if available, otherwise detect from filename
    let osType = info.windows_version || info.linux_distro || detectOsType(info.name);

    // Add ISO type badge
    if (info.iso_type === 'LinuxHybrid') {
      osType += ' (Hybrid)';
    } else if (info.iso_type === 'LinuxLegacy') {
      osType += ' (Legacy)';
    }

    elements.isoVersion.textContent = osType;

    elements.btnNext1.disabled = false;
    console.log('ISO loaded successfully. Type:', info.iso_type, 'Hybrid:', info.is_hybrid);
  } catch (error) {
    console.error('Error loading ISO:', error);
    alert('Failed to load ISO: ' + error);
  }
}

// Convert backend WriteMode enum to string for invoke
function getWriteModeString(mode) {
  switch (mode) {
    case 'WindowsDual': return 'windows_dual';
    case 'DDImage': return 'dd_image';
    case 'ISOExtract': return 'iso_extract';
    case 'Ventoy': return 'ventoy';
    default: return null;  // Use auto-detection
  }
}

function detectOsType(filename) {
  const name = filename.toLowerCase();

  if (name.includes('win11') || name.includes('windows 11') || name.includes('windows_11')) {
    return 'Windows 11';
  } else if (name.includes('win10') || name.includes('windows 10') || name.includes('windows_10')) {
    return 'Windows 10';
  } else if (name.includes('windows')) {
    return 'Windows';
  } else if (name.includes('ubuntu')) {
    return 'Ubuntu';
  } else if (name.includes('debian')) {
    return 'Debian';
  } else if (name.includes('fedora')) {
    return 'Fedora';
  } else if (name.includes('centos') || name.includes('rhel') || name.includes('red hat')) {
    return 'Red Hat / CentOS';
  } else if (name.includes('arch')) {
    return 'Arch Linux';
  } else if (name.includes('mint')) {
    return 'Linux Mint';
  } else if (name.includes('manjaro')) {
    return 'Manjaro';
  } else if (name.includes('opensuse') || name.includes('suse')) {
    return 'openSUSE';
  } else if (name.includes('kali')) {
    return 'Kali Linux';
  } else if (name.includes('pop')) {
    return 'Pop!_OS';
  } else if (name.includes('elementary')) {
    return 'elementary OS';
  } else if (name.includes('macos') || name.includes('osx')) {
    return 'macOS';
  } else {
    return 'ISO Image';
  }
}

function clearIsoSelection() {
  selectedIso = null;
  elements.isoSelector.classList.remove('hidden');
  elements.isoInfo.classList.add('hidden');
  elements.btnNext1.disabled = true;
}

// =================================================================
// Drive Selection
// =================================================================

function setupDriveRefresh() {
  elements.refreshDrives.addEventListener('click', async () => {
    elements.refreshDrives.classList.add('spinning');
    await refreshDriveList();
    setTimeout(() => {
      elements.refreshDrives.classList.remove('spinning');
    }, 500);
  });
}

async function refreshDriveList() {
  try {
    const drives = await invoke('get_usb_drives');
    renderDriveList(drives);
    console.log('Drives found:', drives);
  } catch (error) {
    console.error('Error scanning drives:', error);
    renderDriveList([]);
  }
}

function renderDriveList(drives) {
  elements.driveList.innerHTML = '';

  if (drives.length === 0) {
    elements.driveList.innerHTML = `
      <div class="empty-state">
        <img src="/icons/usb.png" alt="USB" class="empty-icon" />
        <p>No USB drives detected</p>
        <p class="empty-subtext">Insert a USB drive and click refresh</p>
      </div>
    `;
    selectedDrive = null;
    elements.btnNext2.disabled = true;
    return;
  }

  drives.forEach((drive) => {
    const driveEl = document.createElement('div');
    driveEl.className = 'drive-item';
    driveEl.dataset.path = drive.path;

    if (selectedDrive && selectedDrive.path === drive.path) {
      driveEl.classList.add('selected');
    }

    driveEl.innerHTML = `
      <div class="drive-icon">
        <img src="/icons/usb.png" alt="USB" />
      </div>
      <div class="drive-details">
        <p class="drive-name">${escapeHtml(drive.name)}</p>
        <p class="drive-meta">
          <span class="drive-size">${drive.size_formatted}</span>
          <span class="separator">|</span>
          <span class="drive-path">${escapeHtml(drive.path)}</span>
        </p>
      </div>
      <div class="drive-radio"></div>
    `;

    driveEl.addEventListener('click', () => {
      selectDrive(drive, driveEl);
    });

    elements.driveList.appendChild(driveEl);
  });
}

function selectDrive(drive, element) {
  document.querySelectorAll('.drive-item').forEach(el => {
    el.classList.remove('selected');
  });

  element.classList.add('selected');
  selectedDrive = drive;
  elements.btnNext2.disabled = false;

  console.log('Drive selected:', drive);
}

// =================================================================
// Write Process
// =================================================================

function setupWriteButton() {
  elements.btnWrite.addEventListener('click', async () => {
    if (!selectedIso || !selectedDrive) return;

    const confirmed = confirm(
      `WARNING: All data on "${selectedDrive.name}" (${selectedDrive.size_formatted}) will be permanently erased!\n\n` +
      `Are you sure you want to continue?`
    );

    if (confirmed) {
      await startWriteProcess();
    }
  });

  elements.btnCancel.addEventListener('click', async () => {
    await cancelWriteProcess();
  });
}

async function startWriteProcess() {
  try {
    isWriting = true;

    // Hide sections, show progress
    elements.summarySection.classList.add('hidden');
    elements.optionsSection.classList.add('hidden');
    elements.successMessage.classList.add('hidden');
    elements.errorMessage.classList.add('hidden');
    elements.progressSection.classList.remove('hidden');

    // Update buttons
    elements.btnBack3.classList.add('hidden');
    elements.btnWrite.classList.add('hidden');
    elements.btnCancel.classList.remove('hidden');

    // Get options from UI
    const useGpt = document.getElementById('opt-gpt')?.checked ?? true;
    const partitionScheme = useGpt ? 'gpt' : 'mbr';

    // Start the write process with mode and options
    await invoke('start_write_process', {
      isoPath: selectedIso.path,
      drivePath: selectedDrive.path,
      writeMode: selectedWriteMode,
      partitionScheme: partitionScheme,
      targetSystem: 'both'  // Default to UEFI and BIOS
    });

    console.log('Write process started with mode:', selectedWriteMode, 'scheme:', partitionScheme);

    // Start polling for progress
    progressInterval = setInterval(updateProgress, 500);

  } catch (error) {
    console.error('Error starting write:', error);
    showError(`Failed to start write process: ${error}`);
    resetWriteUI();
  }
}

async function updateProgress() {
  try {
    const progress = await invoke('get_write_progress');

    // Update UI - show syncing message when in finalizing stage
    if (progress.stage_name === 'Syncing data...' || progress.stage_name.toLowerCase().includes('sync')) {
      elements.progressStage.textContent = 'Syncing data to USB... This may take a few minutes';
    } else {
      elements.progressStage.textContent = progress.stage_name;
    }
    elements.progressPercent.textContent = `${Math.round(progress.overall_progress * 100)}%`;
    elements.progressBar.style.width = `${progress.overall_progress * 100}%`;

    if (progress.current_file) {
      elements.currentFile.textContent = truncatePath(progress.current_file, 30);
    } else if (progress.stage_name === 'Syncing data...' || progress.stage_name.toLowerCase().includes('sync')) {
      elements.currentFile.textContent = 'Flushing buffers to USB drive...';
    } else {
      elements.currentFile.textContent = '--';
    }

    elements.writeSpeed.textContent = progress.speed;
    elements.writeEta.textContent = progress.eta;

    // Check for completion
    if (progress.is_complete) {
      clearInterval(progressInterval);
      progressInterval = null;
      showSuccess();
    }

    // Check for error
    if (progress.error) {
      clearInterval(progressInterval);
      progressInterval = null;
      showError(progress.error);
    }

  } catch (error) {
    console.error('Error getting progress:', error);
  }
}

async function cancelWriteProcess() {
  try {
    await invoke('cancel_write_process');

    if (progressInterval) {
      clearInterval(progressInterval);
      progressInterval = null;
    }

    showError('Operation cancelled by user');

  } catch (error) {
    console.error('Error cancelling:', error);
  }
}

function resetWriteUI() {
  isWriting = false;
  elements.btnBack3.classList.remove('hidden');
  elements.btnWrite.classList.remove('hidden');
  elements.btnCancel.classList.add('hidden');
  elements.progressSection.classList.add('hidden');
}

function showSuccess() {
  isWriting = false;
  elements.progressSection.classList.add('hidden');
  elements.successMessage.classList.remove('hidden');
  elements.errorMessage.classList.add('hidden');

  // Show Done button instead of write/cancel
  elements.btnBack3.classList.add('hidden');
  elements.btnWrite.classList.add('hidden');
  elements.btnCancel.classList.add('hidden');
  elements.btnDone.classList.remove('hidden');
}

function showError(message) {
  isWriting = false;
  elements.errorText.textContent = message;
  elements.progressSection.classList.add('hidden');
  elements.errorMessage.classList.remove('hidden');
  elements.successMessage.classList.add('hidden');

  // Show back button to try again
  elements.btnBack3.classList.remove('hidden');
  elements.btnWrite.classList.remove('hidden');
  elements.btnCancel.classList.add('hidden');
  elements.btnDone.classList.add('hidden');
}

// =================================================================
// Utilities
// =================================================================

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function truncatePath(path, maxLength) {
  if (path.length <= maxLength) return path;
  const parts = path.split('/');
  const filename = parts.pop();
  if (filename.length >= maxLength) {
    return '...' + filename.slice(-(maxLength - 3));
  }
  return '.../' + filename;
}
