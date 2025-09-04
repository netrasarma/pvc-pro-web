# 🚀 PVC Maker - Complete Google Cloud Run Deployment Guide

## Prerequisites

1. **Google Cloud Account** - Sign up at [cloud.google.com](https://cloud.google.com)
2. **GitHub Account** - For repository hosting
3. **gcloud CLI** - Download from [cloud.google.com/sdk](https://cloud.google.com/sdk/docs/install)
4. **Git** - For version control

---

## Step 1: Set Up Google Cloud Project

### 1.1 Install and Configure gcloud CLI

```bash
# Download and install gcloud CLI from:
# https://cloud.google.com/sdk/docs/install

# After installation, run:
gcloud init
gcloud auth login
```

### 1.2 Use Your Existing Google Cloud Project

```bash
# Set your existing project as default
gcloud config set project pvc-maker

# Verify project is set
gcloud config get-value project
```

### 1.3 Enable Required APIs

```bash
# Enable Cloud Run
gcloud services enable run.googleapis.com

# Enable Cloud Build
gcloud services enable cloudbuild.googleapis.com

# Enable Secret Manager
gcloud services enable secretmanager.googleapis.com

# Enable Container Registry
gcloud services enable containerregistry.googleapis.com
```

### 1.4 Create Service Account

```bash
# Create service account
gcloud iam service-accounts create pvc-pro-sa \
  --description="Service account for PVC Pro Cloud Run" \
  --display-name="PVC Pro Service Account"

# Grant necessary permissions
gcloud projects add-iam-policy-binding pvc-maker \
  --member="serviceAccount:pvc-pro-sa@pvc-maker.iam.gserviceaccount.com" \
  --role="roles/cloudsql.client"

gcloud projects add-iam-policy-binding pvc-maker \
  --member="serviceAccount:pvc-pro-sa@pvc-maker.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

gcloud projects add-iam-policy-binding pvc-maker \
  --member="serviceAccount:pvc-pro-sa@pvc-maker.iam.gserviceaccount.com" \
  --role="roles/storage.objectViewer"

# Create service account key (save this securely)
gcloud iam service-accounts keys create key.json \
  --iam-account=pvc-pro-sa@pvc-maker.iam.gserviceaccount.com
```

---

## Step 2: Set Up Secrets in Google Cloud

### 2.1 Prepare Your Credentials

Make sure you have these files ready:
- `newfirebasekey.json` - Your Firebase service account key
- Your Cashfree credentials (App ID, Secret Key, Webhook Secret)

### 2.2 Create Secrets

```bash
# Navigate to your project directory
cd pvc-maker-web/pvc-pro

# Create Firebase secret
gcloud secrets create firebase-adminsdk --data-file=newfirebasekey.json

# Grant access to service account
gcloud secrets add-iam-policy-binding firebase-adminsdk \
  --member="serviceAccount:pvc-pro-sa@pvc-maker.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

# Create Cashfree secrets (replace with your actual values)
echo -n "your_actual_cashfree_app_id" | gcloud secrets create cashfree-app-id --data-file=-
echo -n "your_actual_cashfree_secret_key" | gcloud secrets create cashfree-secret-key --data-file=-
echo -n "your_actual_cashfree_webhook_secret" | gcloud secrets create cashfree-webhook-secret --data-file=-

# Grant access to Cashfree secrets
for secret in cashfree-app-id cashfree-secret-key cashfree-webhook-secret; do
  gcloud secrets add-iam-policy-binding $secret \
    --member="serviceAccount:pvc-pro-sa@pvc-maker.iam.gserviceaccount.com" \
    --role="roles/secretmanager.secretAccessor"
done
```

---

## Step 3: Set Up GitHub Repository

### 3.1 Create GitHub Repository

1. Go to [github.com](https://github.com) and sign in
2. Click "New repository"
3. Name it `pvc-maker-web` or your preferred name
4. Make it **Public** or **Private** (Private recommended)
5. **DO NOT** initialize with README, .gitignore, or license
6. Click "Create repository"

### 3.2 Initialize and Push Code

```bash
# Navigate to your project directory
cd pvc-maker-web/pvc-pro

# Initialize git (if not already done)
git init

# Add all files
git add .

# Commit files
git commit -m "Initial commit - PVC Maker Flask application"

# Add remote repository (replace with your GitHub username and repo name)
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git

# Rename branch to main (if needed)
git branch -M main

# Push to GitHub
git push -u origin main
```

---

## Step 4: Configure GitHub Secrets

### 4.1 Get Required Values

You need these values:
- **GCP_PROJECT_ID**: `pvc-maker-project`
- **GCP_SA_KEY**: Base64 encoded content of `key.json`
- **GCP_SERVICE_ACCOUNT_EMAIL**: `pvc-pro-sa@pvc-maker-project.iam.gserviceaccount.com`
- **CASHFREE_APP_ID**: Your Cashfree App ID
- **CASHFREE_SECRET_KEY**: Your Cashfree Secret Key
- **CASHFREE_WEBHOOK_SECRET**: Your Cashfree Webhook Secret

### 4.2 Encode Service Account Key

```bash
# On Windows PowerShell:
[System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("key.json"))

# On Linux/Mac:
base64 -w 0 key.json

# On Windows Command Prompt:
certutil -encode key.json key.txt
# Then copy the content between -----BEGIN CERTIFICATE----- and -----END CERTIFICATE-----
```

### 4.3 Add Secrets to GitHub

1. Go to your GitHub repository
2. Click **Settings** tab
3. Click **Secrets and variables** → **Actions**
4. Click **New repository secret**
5. Add each secret:

| Secret Name | Value |
|-------------|--------|
| `GCP_PROJECT_ID` | `pvc-maker-project` |
| `GCP_SA_KEY` | [Base64 encoded key.json content] |
| `GCP_SERVICE_ACCOUNT_EMAIL` | `pvc-pro-sa@pvc-maker-project.iam.gserviceaccount.com` |
| `CASHFREE_APP_ID` | Your Cashfree App ID |
| `CASHFREE_SECRET_KEY` | Your Cashfree Secret Key |
| `CASHFREE_WEBHOOK_SECRET` | Your Cashfree Webhook Secret |

---

## Step 5: Deploy Your Application

### 5.1 Automatic Deployment (Recommended)

Once you've set up the GitHub secrets, every push to the `main` branch will automatically deploy your application.

```bash
# Make any change to trigger deployment
echo "Trigger deployment" >> README.md
git add README.md
git commit -m "Trigger deployment"
git push origin main
```

### 5.2 Manual Deployment (Alternative)

```bash
# Navigate to your project directory
cd pvc-maker-web/pvc-pro

# Build and deploy manually
gcloud builds submit --tag gcr.io/pvc-maker-project/pvc-pro

# Deploy to Cloud Run
gcloud run deploy pvc-pro \
  --image gcr.io/pvc-maker-project/pvc-pro \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars "CASHFREE_APP_ID=YOUR_CASHFREE_APP_ID" \
  --set-env-vars "CASHFREE_SECRET_KEY=YOUR_CASHFREE_SECRET_KEY" \
  --set-env-vars "CASHFREE_WEBHOOK_SECRET=YOUR_WEBHOOK_SECRET" \
  --set-env-vars "FIREBASE_CREDENTIAL_PATH=/secrets/firebase/firebase-adminsdk.json" \
  --update-secrets firebase-adminsdk=/secrets/firebase/firebase-adminsdk.json:latest \
  --service-account pvc-pro-sa@pvc-maker-project.iam.gserviceaccount.com
```

---

## Step 6: Verify Deployment

### 6.1 Check Cloud Run Service

```bash
# List Cloud Run services
gcloud run services list

# Get service details
gcloud run services describe pvc-pro --region=us-central1
```

### 6.2 Get Service URL

```bash
# Get the service URL
gcloud run services describe pvc-pro --region=us-central1 --format="value(status.url)"
```

### 6.3 Check Logs

```bash
# View recent logs
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=pvc-pro" --limit=10
```

---

## Step 7: Update Environment Variables (if needed)

If you need to update environment variables after deployment:

```bash
gcloud run services update pvc-pro \
  --set-env-vars "NEW_VAR=value" \
  --region=us-central1
```

---

## Troubleshooting

### Common Issues:

1. **Build Failures**
   ```bash
   # Check build logs
   gcloud builds list
   gcloud builds log $(gcloud builds list --limit=1 --format="value(ID)")
   ```

2. **Deployment Failures**
   ```bash
   # Check Cloud Run logs
   gcloud logging read "resource.type=cloud_run_revision" --limit=20
   ```

3. **Permission Issues**
   ```bash
   # Verify service account permissions
   gcloud iam service-accounts get-iam-policy pvc-pro-sa@pvc-maker-project.iam.gserviceaccount.com
   ```

4. **Secret Access Issues**
   ```bash
   # Check secret versions
   gcloud secrets versions list firebase-adminsdk
   ```

### Useful Commands:

```bash
# List all services
gcloud run services list

# Update service
gcloud run services update pvc-pro --image gcr.io/pvc-maker-project/pvc-pro:latest

# Delete service
gcloud run services delete pvc-pro

# View service logs
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=pvc-pro"
```

---

## Cost Estimation

- **Cloud Run**: ~$0.000024 per vCPU-second (first 2 million requests free)
- **Cloud Build**: First 120 minutes free per month
- **Secret Manager**: First 6 secrets free
- **Container Registry**: First 0.5 GB free

---

## Security Best Practices

1. ✅ Use environment variables for sensitive data
2. ✅ Store secrets in Secret Manager
3. ✅ Use least-privilege service accounts
4. ✅ Enable HTTPS only
5. ✅ Regularly rotate service account keys
6. ✅ Monitor access logs

---

## Next Steps

1. **Set up monitoring**: Configure Cloud Monitoring alerts
2. **Add custom domain**: Map your domain to Cloud Run
3. **Set up backup**: Configure automated backups
4. **Add SSL**: Cloud Run provides automatic SSL
5. **Scale settings**: Configure concurrency and CPU allocation

---

## Support

If you encounter issues:
1. Check the [Cloud Run documentation](https://cloud.google.com/run/docs)
2. Review [GitHub Actions documentation](https://docs.github.com/en/actions)
3. Check your Cloud Build and Cloud Run logs
4. Verify all secrets and permissions are correctly configured

---

**🎉 Your PVC Maker application is now deployed and ready to use!**

The service will be available at: `https://pvc-pro-[hash]-uc.a.run.app`
