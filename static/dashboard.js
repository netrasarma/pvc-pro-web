// Read user data from JSON script tag
let userData = {};
try {
    const userDataScript = document.getElementById('user-data');
    if (userDataScript) {
        userData = JSON.parse(userDataScript.textContent);
        // Set window variables for backward compatibility
        window.userLoggedIn = userData.userLoggedIn;
        window.userCredits = userData.userCredits;
        window.userName = userData.userName;
        window.userEmail = userData.userEmail;
        window.userMobile = userData.userMobile;
    }
} catch (error) {
    console.error('Error parsing user data:', error);
}

console.log("Dashboard JavaScript loaded. User logged in:", window.userLoggedIn);

let currentPaymentAmount = 0;
let selectedFiles = [];
let processedDocuments = [];

// UI Functions
function toggleCollapse(sectionId) {
    const section = document.getElementById(sectionId);
    const isExpanded = section.classList.toggle('expanded');
    const button = document.querySelector(`button[onclick="toggleCollapse('${sectionId}')"]`);
    const arrow = button.querySelector('span:last-child');
    arrow.style.transform = isExpanded ? 'rotate(180deg)' : 'rotate(0deg)';
}

function showRechargeAmountInput() {
    document.getElementById('rechargeAmountModal').classList.remove('hidden');
    document.getElementById('recharge-amount').value = '';
    document.getElementById('recharge-amount').focus();
}

function hideRechargeAmountInput() {
    document.getElementById('rechargeAmountModal').classList.add('hidden');
}

function showPaymentProcessing() {
    document.getElementById('paymentProcessingModal').classList.remove('hidden');
}

function hidePaymentProcessing() {
    document.getElementById('paymentProcessingModal').classList.add('hidden');
}

function showPaymentSuccess(message) {
    document.getElementById('success-message').textContent = message;
    document.getElementById('paymentSuccessModal').classList.remove('hidden');
}

function hidePaymentSuccessModal() {
    document.getElementById('paymentSuccessModal').classList.add('hidden');
    location.reload(); // Refresh to update credits
}

// File Handling for Multiple Documents
function handleDragOver(e) {
    e.preventDefault();
    e.stopPropagation();
    document.getElementById('file-upload-area').classList.add('dragover');
}

function handleDrop(e) {
    e.preventDefault();
    e.stopPropagation();
    document.getElementById('file-upload-area').classList.remove('dragover');
    handleFileSelect(e.dataTransfer.files);
}

function handleFileSelect(files) {
    if (files.length > 0) {
        Array.from(files).forEach(file => {
            if (!selectedFiles.some(f => f.name === file.name && f.size === file.size)) {
                selectedFiles.push(file);
            }
        });
        updateSelectedFilesList();
        updateCreditCost();
    }
}

function updateSelectedFilesList() {
    const filesList = document.getElementById('selected-files-list');
    const container = document.getElementById('selected-files-container');
    
    filesList.innerHTML = '';
    
    if (selectedFiles.length > 0) {
        container.classList.remove('hidden');
        
        selectedFiles.forEach((file, index) => {
            const fileItem = document.createElement('div');
            fileItem.className = 'flex justify-between items-center bg-white p-2 rounded border';
            fileItem.innerHTML = `
                <div class="flex-1">
                    <p class="font-medium text-sm">${file.name}</p>
                    <p class="text-xs text-gray-500">${formatFileSize(file.size)}</p>
                </div>
                <button onclick="removeFile(${index})" class="ml-2 text-red-600 hover:text-red-800">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                    </svg>
                </button>
            `;
            filesList.appendChild(fileItem);
        });
    } else {
        container.classList.add('hidden');
    }
}

function removeFile(index) {
    selectedFiles.splice(index, 1);
    updateSelectedFilesList();
    updateCreditCost();
}

function addMoreFiles() {
    document.getElementById('file-input').click();
}

function updateCreditCost() {
    const creditCost = selectedFiles.length;
    document.getElementById('credit-cost').textContent = creditCost;
    document.getElementById('process-button-text').textContent = 
        `Process Documents (${creditCost} Credit${creditCost !== 1 ? 's' : ''})`;
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Payment Integration (Razorpay)
document.getElementById('recharge-amount-form').addEventListener('submit', function (e) {
    e.preventDefault();
    const amountInput = document.getElementById('recharge-amount');
    const amount = parseInt(amountInput.value, 10);
    
    if (isNaN(amount) || amount < 100) {
        alert('Please enter a valid amount of at least ₹100.');
        return;
    }
    
    hideRechargeAmountInput();
    initiateRazorpayPayment(amount);
});

function initiateRazorpayPayment(amount) {
    if (!window.userLoggedIn) {
        alert("Please log in to make a payment.");
        window.location.href = '/login';
        return;
    }

    currentPaymentAmount = amount;
    showPaymentProcessing();

    // Create order on server
    fetch('/create_razorpay_order', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            amount: amount * 100, // Razorpay expects amount in paise
            currency: 'INR',
            receipt: 'credit_recharge_' + Date.now()
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            hidePaymentProcessing();
            alert('Error: ' + data.error);
            return;
        }

        const options = {
            key: data.key_id, // Your Razorpay Key ID from server
            amount: data.amount,
            currency: data.currency,
            name: 'PVC Pro',
            description: 'Credit Recharge',
            order_id: data.order_id,
            handler: function(response) {
                // Handle successful payment
                verifyPayment(response);
            },
            prefill: {
                name: window.userName || '',
                email: window.userEmail || '',
                contact: window.userMobile || ''
            },
            theme: {
                color: '#2563eb'
            }
        };

        const rzp = new Razorpay(options);
        rzp.open();
        hidePaymentProcessing();
    })
    .catch(error => {
        hidePaymentProcessing();
        console.error('Error:', error);
        alert('Failed to initiate payment. Please try again.');
    });
}

function verifyPayment(paymentResponse) {
    showPaymentProcessing();
    
    fetch('/verify_razorpay_payment', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            razorpay_order_id: paymentResponse.razorpay_order_id,
            razorpay_payment_id: paymentResponse.razorpay_payment_id,
            razorpay_signature: paymentResponse.razorpay_signature,
            amount: currentPaymentAmount
        })
    })
    .then(response => response.json())
    .then(data => {
        hidePaymentProcessing();
        if (data.success) {
            showPaymentSuccess(`Successfully added ${currentPaymentAmount} credits to your account!`);
        } else {
            alert('Payment verification failed: ' + data.error);
        }
    })
    .catch(error => {
        hidePaymentProcessing();
        console.error('Verification error:', error);
        alert('Payment verification failed. Please contact support.');
    });
}

// Document Processing for Multiple Files
document.getElementById('processing-form').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const docType = document.getElementById('doc-type').value;
    
    if (selectedFiles.length === 0) {
        alert('Please select at least one file to process.');
        return;
    }

    if (!docType) {
        alert('Please select a document type.');
        return;
    }

    // Check if user has enough credits
    const requiredCredits = selectedFiles.length;
    if (window.userLoggedIn && window.userCredits < requiredCredits) {
        alert(`Insufficient credits! You need ${requiredCredits} credits but only have ${window.userCredits}. Please recharge your account.`);
        return;
    }

    const processButton = document.querySelector('#processing-form button[type="submit"]');
    const buttonText = document.getElementById('process-button-text');
    const spinner = document.getElementById('processing-spinner');

    buttonText.textContent = `Processing ${selectedFiles.length} document${selectedFiles.length !== 1 ? 's' : ''}...`;
    spinner.classList.remove('hidden');
    processButton.disabled = true;

    processedDocuments = [];
    let processedCount = 0;
    let errors = [];

    // Process each file sequentially using the new password-aware function
    for (let i = 0; i < selectedFiles.length; i++) {
        const file = selectedFiles[i];
        const result = await processSingleFile(file, docType, processedDocuments, errors);
        if (result) {
            processedCount++;
        }
    }

    // Update UI
    if (processedCount > 0) {
        displayProcessedDocuments();
        document.getElementById('processed-documents').classList.remove('hidden');
        document.getElementById('total-processed-count').textContent = processedCount;
        
        // Update credit display in UI
        const newCredits = window.userCredits - processedCount;
        window.userCredits = newCredits;
        
        // Update all credit displays
        document.querySelectorAll('.credit-display').forEach(el => {
            el.textContent = newCredits;
        });
        
        // Update sidebar credit display
        const sidebarCredit = document.querySelector('.sidebar-credit');
        if (sidebarCredit) {
            sidebarCredit.textContent = newCredits;
        }
        
        // Show success message
        alert(`Successfully processed ${processedCount} document${processedCount !== 1 ? 's' : ''}! ${processedCount} credit${processedCount !== 1 ? 's' : ''} deducted.`);
        
        // Instead of full reload, fetch updated user data and recent activity
        updateUserDashboardData();
    }

    if (errors.length > 0) {
        alert('Some files failed to process:\n' + errors.join('\n'));
    }

    // Reset UI
    buttonText.textContent = 'Process Documents';
    spinner.classList.add('hidden');
    processButton.disabled = false;
});

function displayProcessedDocuments() {
    const processedFilesList = document.getElementById('processed-files-list');
    processedFilesList.innerHTML = '';
    
    processedDocuments.forEach((doc, index) => {
        const docCard = document.createElement('div');
        docCard.className = 'bg-white p-4 rounded-lg border mb-4';
        docCard.innerHTML = `
            <div class="flex justify-between items-center mb-3">
                <h4 class="font-semibold text-gray-800">${doc.fileName}</h4>
                <span class="text-sm text-gray-500">${doc.timestamp.toLocaleTimeString()}</span>
            </div>
            
            <!-- Image Previews -->
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                ${doc.front ? `
                <div class="text-center">
                    <h5 class="font-medium text-gray-700 mb-2">Front Side</h5>
                    <img src="data:image/png;base64,${doc.front}" 
                         alt="Front side preview" 
                         class="max-w-full h-auto rounded-lg border shadow-sm mx-auto max-h-48 object-contain">
                </div>
                ` : ''}
                
                ${doc.back ? `
                <div class="text-center">
                    <h5 class="font-medium text-gray-700 mb-2">Back Side</h5>
                    <img src="data:image/png;base64,${doc.back}" 
                         alt="Back side preview" 
                         class="max-w-full h-auto rounded-lg border shadow-sm mx-auto max-h-48 object-contain">
                </div>
                ` : ''}
            </div>
            
            <!-- Download Buttons -->
            <div class="flex space-x-4 justify-center">
                ${doc.front ? `
                <button onclick="downloadSingleFile(${index}, 'front')" class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors text-sm">
                    Download Front
                </button>
                ` : ''}
                
                ${doc.back ? `
                <button onclick="downloadSingleFile(${index}, 'back')" class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors text-sm">
                    Download Back
                </button>
                ` : ''}
            </div>
        `;
        processedFilesList.appendChild(docCard);
    });
}

function downloadSingleFile(index, side) {
    const doc = processedDocuments[index];
    if (doc && doc[side]) {
        const link = document.createElement('a');
        link.href = `data:image/png;base64,${doc[side]}`;
        link.download = `pvc_${doc.fileName.replace(/\.[^/.]+$/, '')}_${side}_${Date.now()}.png`;
        link.click();
    }
}

function downloadAllProcessedFiles() {
    if (processedDocuments.length === 0) {
        alert('No processed documents available for download.');
        return;
    }

    // Check if JSZip is available
    if (typeof JSZip === 'undefined') {
        alert('ZIP functionality not available. Downloading files individually...');
        downloadFilesIndividually();
        return;
    }

    alert('Creating ZIP archive with all processed documents... This may take a moment.');
    
    try {
        // Create a zip file using JSZip
        const zip = new JSZip();
        let fileCount = 0;

        processedDocuments.forEach((doc, index) => {
            const baseName = doc.fileName.replace(/\.[^/.]+$/, '');

            if (doc.front) {
                // doc.front is base64 string without data URL prefix
                zip.file(`${baseName}_front.png`, doc.front, {base64: true});
                fileCount++;
            }

            if (doc.back) {
                // doc.back is base64 string without data URL prefix
                zip.file(`${baseName}_back.png`, doc.back, {base64: true});
                fileCount++;
            }
        });

        // Generate and download the zip file
        zip.generateAsync({type: 'blob'})
            .then(function(content) {
                const link = document.createElement('a');
                link.href = URL.createObjectURL(content);
                link.download = `pvc_processed_documents_${Date.now()}.zip`;
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                
                alert(`Successfully downloaded ${fileCount} files in ZIP archive!`);
            })
            .catch(function(error) {
                console.error('Error creating ZIP file:', error);
                alert('Failed to create ZIP archive. Please try downloading files individually.');
                downloadFilesIndividually();
            });
    } catch (error) {
        console.error('Error with ZIP creation:', error);
        alert('Failed to create ZIP archive. Please try downloading files individually.');
        downloadFilesIndividually();
    }
}

function downloadFilesIndividually() {
    alert('Downloading files individually... This may take a moment.');
    
    // Download each file individually with delays
    processedDocuments.forEach((doc, index) => {
        setTimeout(() => {
            if (doc.front) downloadSingleFile(index, 'front');
        }, index * 500);
        
        setTimeout(() => {
            if (doc.back) downloadSingleFile(index, 'back');
        }, (index * 500) + 250);
    });
}

// Support Functions - Fully Implemented
function showPurchaseHistory() {
    document.getElementById('purchaseHistoryModal').classList.remove('hidden');
}

function hidePurchaseHistory() {
    document.getElementById('purchaseHistoryModal').classList.add('hidden');
}

function showProfileSettings() {
    document.getElementById('profileSettingsModal').classList.remove('hidden');
}

function hideProfileSettings() {
    document.getElementById('profileSettingsModal').classList.add('hidden');
}

function showHelpCenter() {
    document.getElementById('helpCenterModal').classList.remove('hidden');
}

function hideHelpCenter() {
    document.getElementById('helpCenterModal').classList.add('hidden');
}

function showContactSupport() {
    document.getElementById('contactSupportModal').classList.remove('hidden');
}

function hideContactSupport() {
    document.getElementById('contactSupportModal').classList.add('hidden');
}

// Profile Settings Form Submission
document.getElementById('profile-settings-form')?.addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const formData = {
        name: document.getElementById('profile-name').value,
        mobile: document.getElementById('profile-mobile').value
    };
    
    try {
        const response = await fetch('/api/update_profile', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(formData)
        });
        
        const data = await response.json();
        
        if (response.ok) {
            alert('Profile updated successfully!');
            hideProfileSettings();
            // Update user data in UI if needed
            if (data.user) {
                window.userName = data.user.name;
                window.userMobile = data.user.mobile;
            }
        } else {
            alert('Error updating profile: ' + data.error);
        }
    } catch (error) {
        console.error('Profile update error:', error);
        alert('Failed to update profile. Please try again.');
    }
});

// Contact Support Form Submission
document.getElementById('contact-support-form')?.addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const formData = {
        subject: document.getElementById('support-subject').value,
        message: document.getElementById('support-message').value,
        email: document.getElementById('support-email').value
    };
    
    try {
        const response = await fetch('/api/contact_support', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(formData)
        });
        
        const data = await response.json();
        
        if (response.ok) {
            alert('Support message sent successfully! We will get back to you soon.');
            hideContactSupport();
            // Clear form
            document.getElementById('support-subject').value = '';
            document.getElementById('support-message').value = '';
        } else {
            alert('Error sending message: ' + data.error);
        }
    } catch (error) {
        console.error('Support message error:', error);
        alert('Failed to send message. Please try again.');
    }
});

// Close modals when clicking outside
document.addEventListener('click', function(e) {
    const modals = [
        'purchaseHistoryModal',
        'profileSettingsModal', 
        'helpCenterModal',
        'contactSupportModal',
        'rechargeAmountModal',
        'paymentProcessingModal',
        'paymentSuccessModal'
    ];
    
    modals.forEach(modalId => {
        const modal = document.getElementById(modalId);
        if (modal && !modal.classList.contains('hidden') && e.target === modal) {
            switch(modalId) {
                case 'purchaseHistoryModal':
                    hidePurchaseHistory();
                    break;
                case 'profileSettingsModal':
                    hideProfileSettings();
                    break;
                case 'helpCenterModal':
                    hideHelpCenter();
                    break;
                case 'contactSupportModal':
                    hideContactSupport();
                    break;
                case 'rechargeAmountModal':
                    hideRechargeAmountInput();
                    break;
                case 'paymentProcessingModal':
                    hidePaymentProcessing();
                    break;
                case 'paymentSuccessModal':
                    hidePaymentSuccessModal();
                    break;
            }
        }
    });
});

// Close modals with Escape key
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        if (!document.getElementById('purchaseHistoryModal').classList.contains('hidden')) {
            hidePurchaseHistory();
        } else if (!document.getElementById('profileSettingsModal').classList.contains('hidden')) {
            hideProfileSettings();
        } else if (!document.getElementById('helpCenterModal').classList.contains('hidden')) {
            hideHelpCenter();
        } else if (!document.getElementById('contactSupportModal').classList.contains('hidden')) {
            hideContactSupport();
        } else if (!document.getElementById('rechargeAmountModal').classList.contains('hidden')) {
            hideRechargeAmountInput();
        }
    }
});

// Initialize
document.addEventListener('DOMContentLoaded', function() {
    console.log('Dashboard initialized');
    // Add any initialization code here
    // Optionally, fetch latest user data on load
    // updateUserDashboardData();
});

// Fetch updated user credits and recent activity and update UI dynamically
async function updateUserDashboardData() {
    try {
        const response = await fetch('/api/user_dashboard_data');
        if (!response.ok) {
            console.error('Failed to fetch user dashboard data');
            return;
        }
        const data = await response.json();
        if (data.credits !== undefined) {
            window.userCredits = data.credits;
            // Update credit displays
            document.querySelectorAll('.credit-display').forEach(el => {
                el.textContent = data.credits;
            });
            const sidebarCredit = document.querySelector('.sidebar-credit');
            if (sidebarCredit) {
                sidebarCredit.textContent = data.credits;
            }
        }
        if (data.recent_transactions) {
            updateRecentActivityUI(data.recent_transactions);
        }
    } catch (error) {
        console.error('Error updating dashboard data:', error);
    }
}

// Update recent activity section UI
function updateRecentActivityUI(transactions) {
    const recentActivityDiv = document.getElementById('recent-activity');
    if (!极速飞艇开奖直播recentActivityDiv) return;

    if (transactions.length === 0) {
        recentActivityDiv.innerHTML = '<p class="text-gray-500 text-center py-8">No recent activity found.</p>';
        return;
    }

    let html = '<div class="space-y-3">';
    transactions.slice(0, 5).forEach(tx => {
        const isDebit = tx.type === 'DEBIT';
        const amountAbs = Math.abs(tx.amount);
        const dateStr = tx.timestamp ? new Date(tx.timestamp).toLocaleString() : 'N/A';
        html += `
            <div class="transaction-item ${isDebit ? 'debit' : 'credit'} p极速飞艇开奖直播-4 rounded-lg border">
                <div class="flex justify-between items-center">
                    <div>
                        <p class="font-medium text-gray-800">${tx.type}</p>
                        <p class="text-sm text-gray-600">${dateStr}</p>
                    </div>
                    <div class="text-right">
                        <p class="font-semibold ${isDebit ? 'text-red-600' : 'text-green-600'}">
                            ${isDebit ? '-' : '+'}${amountAbs} credits
                        </p>
                        <极速飞艇开奖直播p class="text-sm text-gray-600">Balance: ${tx.balance_after}</p>
                    </div>
                </div>
            </div>
        `;
    });
    html += '</div>';
    recentActivityDiv.innerHTML = html;
}

// Function to process a single file with password handling
async function processSingleFile(file, docType, processedDocuments, errors) {
    let password = null;
    let retryCount = 0;
    const maxRetries = 3;
    
    while (retryCount < maxRetries) {
        try {
            const formData = new FormData();
            formData.append('file', file);
            formData.append('doc_type', docType);
            if (password) {
                formData.append('password', password);
            }
            
            console.log(`Processing file: ${file.name}, type: ${file.type}, size: ${file.size}`);
            
            const response = await fetch('/process', {
                method: 'POST',
                body: formData
            });
            
            console.log(`Response status: ${response.status}, ${response.statusText}`);
            
            const result = await response.json();
            console.log('Processing result:', result);
            
            if (response.ok) {
                processedDocuments.push({
                    fileName: file.name,
                    front: result.front,
                    back: result.back,
                    timestamp: new Date()
                });
                console.log(`Successfully processed: ${file.name}`);
                return true; // Success, return true to indicate success
            } else {
                if (result.error === "PASSWORD_REQUIRED" && retryCount < maxRetries - 1) {
                    // Show password prompt
                    password = await showPasswordPrompt(file.name, result.message);
                    if (password === null) {
                        // User cancelled
                        errors.push(`${file.name}: Processing cancelled by user`);
                        return;
                    }
                    retryCount++;
                    continue; // Retry with password
                } else {
                    errors.push(`${file.name}: ${result.error || result.message}`);
                    console.error(`Processing failed for ${file.name}:`, result.error);
                    return; // Other error, exit the function
                }
            }
        } catch (error) {
            errors.push(`${file.name}: Failed to process`);
            console.error('Error processing document:', error);
            return; // Network error, exit the function
        }
    }
    
    if (retryCount >= maxRetries) {
        errors.push(`${file.name}: Maximum password attempts exceeded`);
    }
}

// Show password prompt modal
function showPasswordPrompt(fileName, errorMessage) {
    return new Promise((resolve) => {
        const modal = document.getElementById('passwordPromptModal');
        const fileNameElement = document.getElementById('password-prompt-file-name');
        const errorMessageElement = document.getElementById('password-prompt-error');
        const passwordInput = document.getElementById('password-input');
        const submitButton = document.getElementById('password-submit');
        const cancelButton = document.getElementById('password-cancel');
        
        fileNameElement.textContent = fileName;
        errorMessageElement.textContent = errorMessage || 'This PDF is password protected. Please enter the password to continue.';
        passwordInput.value = '';
        
        modal.classList.remove('hidden');
        passwordInput.focus();
        
        function cleanup() {
            modal.classList.add('hidden');
            submitButton.removeEventListener('click', submitHandler);
            cancelButton.removeEventListener('click', cancelHandler);
            passwordInput.removeEventListener('keypress', keypressHandler);
        }
        
        function submitHandler() {
            const password = passwordInput.value.trim();
            cleanup();
            resolve(password || ''); // Empty string if no password entered
        }
        
        function cancelHandler() {
            cleanup();
            resolve(null); // Null means user cancelled
        }
        
        function keypressHandler(e) {
            if (e.key === 'Enter') {
                submitHandler();
            }
        }
        
        submitButton.addEventListener('click', submitHandler);
        cancelButton.addEventListener('click', cancelHandler);
        passwordInput.addEventListener('keypress', keypressHandler);
    });
}
