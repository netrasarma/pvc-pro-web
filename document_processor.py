from PIL import Image, ImageDraw, ImageFont
import fitz  # PyMuPDF
import cv2
import numpy as np
import io
import os
from scipy import ndimage

class AadharProcessor:
    def __init__(self, file_stream, password=None, add_mobile=False, mobile_number=""):
        self.file_stream = file_stream
        self.password = password
        self.add_mobile = add_mobile
        self.mobile_number = mobile_number
        self.pdf_document = None
        self.front_image = None
        self.back_image = None
        self.cropped_front = None
        self.cropped_back = None
        self.pvc_width = 1012
        self.pvc_height = 638

    def process(self):
        try:
            self.load_pdf()
            self.extract_pages()
            self.auto_crop()
            return self.get_processed_images()
        except Exception as e:
            raise Exception(f"Aadhar processing failed: {str(e)}")

    def load_pdf(self):
        try:
            self.pdf_document = fitz.open(stream=self.file_stream, filetype="pdf")
            if self.pdf_document.needs_pass:
                if not self.password or not self.pdf_document.authenticate(self.password):
                    raise Exception("PDF is password protected and the provided password is not correct.")
        except Exception as e:
            raise Exception(f"Failed to load PDF: {str(e)}")

    def extract_pages(self):
        if not self.pdf_document:
            return

        if len(self.pdf_document) >= 1:
            page = self.pdf_document[0]
            pix = page.get_pixmap(matrix=fitz.Matrix(3, 3))
            img_data = pix.tobytes("ppm")
            full_image = Image.open(io.BytesIO(img_data))

            if len(self.pdf_document) >= 2:
                self.front_image = full_image
                page = self.pdf_document[1]
                pix = page.get_pixmap(matrix=fitz.Matrix(3, 3))
                img_data = pix.tobytes("ppm")
                self.back_image = Image.open(io.BytesIO(img_data))
            else:
                self.split_front_back_from_single_page(full_image)

    def split_front_back_from_single_page(self, image):
        width, height = image.size
        reference_width = 2550
        reference_height = 3300
        reference_front_left = 206
        reference_front_right = 1254
        reference_front_top = 2397
        reference_front_bottom = 3051
        reference_back_left = 1298
        reference_back_right = 2346
        reference_back_top = 2397
        reference_back_bottom = 3051

        scale_x = width / reference_width
        scale_y = height / reference_height

        front_left = int(reference_front_left * scale_x)
        front_right = int(reference_front_right * scale_x)
        front_top = int(reference_front_top * scale_y)
        front_bottom = int(reference_front_bottom * scale_y)

        back_left = int(reference_back_left * scale_x)
        back_right = int(reference_back_right * scale_x)
        back_top = int(reference_back_top * scale_y)
        back_bottom = int(reference_back_bottom * scale_y)

        self.front_image = image.crop((front_left, front_top, front_right, front_bottom))
        self.back_image = image.crop((back_left, back_top, back_right, back_bottom))

    def auto_crop(self):
        if self.front_image:
            self.cropped_front = self.crop_aadhar_card(self.front_image)
            if self.add_mobile and self.mobile_number:
                self.cropped_front = self.add_mobile_number(self.cropped_front)
        if self.back_image:
            self.cropped_back = self.crop_aadhar_card(self.back_image)

    def crop_aadhar_card(self, image):
        cv_image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
        original_height, original_width = cv_image.shape[:2]
        gray = cv2.cvtColor(cv_image, cv2.COLOR_BGR2GRAY)
        blurred = cv2.GaussianBlur(gray, (5, 5), 0)
        thresh = cv2.adaptiveThreshold(blurred, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2)
        kernel = np.ones((3,3), np.uint8)
        thresh = cv2.morphologyEx(thresh, cv2.MORPH_CLOSE, kernel)
        thresh = cv2.morphologyEx(thresh, cv2.MORPH_OPEN, kernel)
        edges = cv2.Canny(blurred, 50, 150)
        contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

        valid_contours = []
        min_area = (original_width * original_height) * 0.1
        max_area = (original_width * original_height) * 0.9

        for contour in contours:
            area = cv2.contourArea(contour)
            if min_area < area < max_area:
                x, y, w, h = cv2.boundingRect(contour)
                aspect_ratio = w / h if h > 0 else 0
                if 1.2 < aspect_ratio < 2.0:
                    valid_contours.append((contour, area, x, y, w, h))

        if valid_contours:
            valid_contours.sort(key=lambda x: x[1], reverse=True)
            best_contour, area, x, y, w, h = valid_contours[0]
            padding = min(20, w//20, h//20)
            x = max(0, x - padding)
            y = max(0, y - padding)
            w = min(original_width - x, w + 2 * padding)
            h = min(original_height - y, h + 2 * padding)
            cropped = image.crop((x, y, x + w, y + h))
        else:
            cropped = self.template_based_crop(image)
            if cropped is None:
                width, height = image.size
                target_aspect = 1.6
                if width / height > target_aspect:
                    new_width = int(height * target_aspect)
                    x = (width - new_width) // 2
                    cropped = image.crop((x, 0, x + new_width, height))
                else:
                    new_height = int(width / target_aspect)
                    y = (height - new_height) // 2
                    cropped = image.crop((0, y, width, y + new_height))

        return cropped.resize((self.pvc_width, self.pvc_height), Image.Resampling.LANCZOS)

    def template_based_crop(self, image):
        try:
            front_ref_path = "pvc-maker-web/backend/templates/FRONT.png"
            if os.path.exists(front_ref_path):
                cv_image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
                gray = cv2.cvtColor(cv_image, cv2.COLOR_BGR2GRAY)
                ref_image = cv2.imread(front_ref_path)
                if ref_image is not None:
                    ref_gray = cv2.cvtColor(ref_image, cv2.COLOR_BGR2GRAY)
                    best_match = None
                    best_val = 0
                    for scale in [0.5, 0.7, 1.0, 1.3, 1.5]:
                        ref_height, ref_width = ref_gray.shape
                        new_width = int(ref_width * scale)
                        new_height = int(ref_height * scale)
                        if new_width < gray.shape[1] and new_height < gray.shape[0]:
                            scaled_ref = cv2.resize(ref_gray, (new_width, new_height))
                            result = cv2.matchTemplate(gray, scaled_ref, cv2.TM_CCOEFF_NORMED)
                            _, max_val, _, max_loc = cv2.minMaxLoc(result)
                            if max_val > best_val:
                                best_val = max_val
                                best_match = (max_loc, new_width, new_height)
                    if best_match and best_val > 0.3:
                        (x, y), w, h = best_match
                        padding = 20
                        x = max(0, x - padding)
                        y = max(0, y - padding)
                        w = min(image.width - x, w + 2 * padding)
                        h = min(image.height - y, h + 2 * padding)
                        return image.crop((x, y, x + w, y + h))
            return None
        except Exception as e:
            print(f"Template matching failed: {e}")
            return None

    def add_mobile_number(self, image):
        img_copy = image.copy()
        draw = ImageDraw.Draw(img_copy)
        try:
            font = ImageFont.truetype("arial.ttf", 24)
        except:
            font = ImageFont.load_default()
        width, height = img_copy.size
        cover_height = 60
        cover_y = height - cover_height - 20
        draw.rectangle([20, cover_y, width - 20, cover_y + cover_height], fill='white', outline='white')
        mobile_text = f"Mobile: {self.mobile_number}"
        bbox = draw.textbbox((0, 0), mobile_text, font=font)
        text_width = bbox[2] - bbox[0]
        text_x = (width - text_width) // 2
        text_y = cover_y + 15
        draw.text((text_x, text_y), mobile_text, fill='black', font=font)
        return img_copy

    def get_processed_images(self):
        images = {}
        if self.cropped_front:
            images['front'] = self.cropped_front
        if self.cropped_back:
            images['back'] = self.cropped_back
        return images

class PanProcessor:
    def __init__(self, file_stream, password=None):
        self.file_stream = file_stream
        self.password = password
        self.pdf_document = None
        self.full_image = None
        self.front_image = None
        self.back_image = None
        self.cropped_front = None
        self.cropped_back = None
        self.pvc_width = 1012
        self.pvc_height = 638

    def process(self):
        try:
            self.load_pdf()
            self.auto_crop()
            return self.get_processed_images()
        except Exception as e:
            raise Exception(f"PAN processing failed: {str(e)}")

    def load_pdf(self):
        try:
            self.pdf_document = fitz.open(stream=self.file_stream, filetype="pdf")
            if self.pdf_document.needs_pass:
                if not self.password or not self.pdf_document.authenticate(self.password):
                    # Attempt to use a default password if none is provided
                    if not self.pdf_document.authenticate(""):
                        raise Exception("PDF is password protected and the provided password is not correct.")
            
            if len(self.pdf_document) > 0:
                page = self.pdf_document[0]
                pix = page.get_pixmap(matrix=fitz.Matrix(3, 3))
                img_data = pix.tobytes("ppm")
                self.full_image = Image.open(io.BytesIO(img_data))

        except Exception as e:
            raise Exception(f"Failed to load PDF: {str(e)}")

    def auto_crop(self):
        if not self.full_image:
            return

        # Convert PIL image to OpenCV format for computer vision processing
        cv_image = cv2.cvtColor(np.array(self.full_image), cv2.COLOR_RGB2BGR)
        
        # Use advanced computer vision to detect PAN card boundaries
        try:
            # First try the advanced contour detection method
            success = self.detect_pan_cards_advanced(cv_image)
            if not success:
                print("Advanced PAN detection failed, falling back to coordinates")
                self.fallback_to_coordinates()
        except Exception as e:
            print(f"Advanced PAN detection failed with error: {e}, falling back to coordinates")
            self.fallback_to_coordinates()

    def detect_pan_cards_advanced(self, cv_image):
        """Advanced PAN card detection using computer vision"""
        # Multiple preprocessing techniques to handle different PAN card formats
        gray = cv2.cvtColor(cv_image, cv2.COLOR_BGR2GRAY)
        H, W = gray.shape[:2]
        img_area = W * H
        
        print(f"Image dimensions: {W}x{H}, Area: {img_area}")
        
        # Try multiple thresholding methods
        _, th1 = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        th2 = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2)
        edges = cv2.Canny(gray, 50, 150)
        
        candidates = []
        
        # Additional preprocessing variations
        preprocessing_variations = [
            ("Original", gray),
            ("GaussianBlur", cv2.GaussianBlur(gray, (3, 3), 0)),
            ("MedianBlur", cv2.medianBlur(gray, 3)),
            ("BilateralFilter", cv2.bilateralFilter(gray, 9, 75, 75))
        ]
        
        for method_name, processed_gray in preprocessing_variations:
            for thresh_name, thresh_method in [("Otsu", th1), ("Adaptive", th2), ("Canny", edges)]:
                try:
                    contours, _ = cv2.findContours(thresh_method, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
                    print(f"{method_name} + {thresh_name}: Found {len(contours)} contours")
                    
                    for i, c in enumerate(contours):
                        area = cv2.contourArea(c)
                        # Filter by area - PAN cards should be significant but not too large
                        if area < 0.02 * img_area or area > 0.8 * img_area:
                            continue
                        
                        # Get bounding rectangle
                        x, y, w, h = cv2.boundingRect(c)
                        
                        # Filter by aspect ratio (PVC card aspect ratio ~1.585)
                        aspect_ratio = w / float(h)
                        if 1.2 <= aspect_ratio <= 2.0:  # Wider range for PAN cards
                            # Check if this looks like a card (solid rectangle with text)
                            roi = processed_gray[y:y+h, x:x+w]
                            if roi.size > 0:
                                # Calculate text density (non-white pixels)
                                _, text_mask = cv2.threshold(roi, 200, 255, cv2.THRESH_BINARY_INV)
                                text_density = np.sum(text_mask > 0) / float(roi.size)
                                
                                # PAN cards should have moderate text density
                                if 0.05 <= text_density <= 0.7:
                                    # Create quadrilateral from bounding rectangle
                                    quad = np.array([[x, y], [x+w, y], [x+w, y+h], [x, y+h]], dtype="float32")
                                    candidates.append((quad, area, text_density, x, y, w, h))
                                    print(f"  Candidate found: area={area}, aspect={aspect_ratio:.2f}, density={text_density:.2f}, pos=({x},{y})")
                except Exception as e:
                    print(f"Contour detection failed for {method_name} + {thresh_name}: {e}")
                    continue
        
        print(f"Total candidates found: {len(candidates)}")
        
        # Remove duplicates and sort by best candidates
        unique_candidates = []
        seen_locations = set()
        
        for quad, area, density, x, y, w, h in candidates:
            # Check if we've seen a similar location (within 10% of image dimensions)
            location_key = (int(x / (W * 0.1)), int(y / (H * 0.1)))
            
            if location_key not in seen_locations:
                unique_candidates.append((quad, area, density, x, y, w, h))
                seen_locations.add(location_key)
        
        # Sort by area (largest first) and then by text density (moderate density preferred)
        unique_candidates.sort(key=lambda x: (-x[1], -abs(x[2] - 0.3)))  # Prefer density around 0.3
        
        # Select top 2 candidates for front and back
        if len(unique_candidates) >= 2:
            # Take top 2 by area, then sort by Y position
            top2 = unique_candidates[:2]
            top2_sorted = sorted(top2, key=lambda x: x[4])  # Sort by Y position
            
            # Warp to standard size
            CR80_SIZE_300 = (1012, 638)
            
            def order_quad(pts):
                rect = np.zeros((4, 2), dtype="float32")
                s = pts.sum(axis=1)
                rect[0] = pts[np.argmin(s)]  # top-left
                rect[2] = pts[np.argmax(s)]  # bottom-right
                diff = np.diff(pts, axis=1)
                rect[1] = pts[np.argmin(diff)]  # top-right
                rect[3] = pts[np.argmax(diff)]  # bottom-left
                return rect
            
            def warp_to_cr80(img, quad, size):
                rect = order_quad(quad)
                dst = np.array([[0, 0], [size[0]-1, 0], [size[0]-1, size[1]-1], [0, size[1]-1]], dtype="float32")
                M = cv2.getPerspectiveTransform(rect, dst)
                warped = cv2.warpPerspective(img, M, size, flags=cv2.INTER_CUBIC)
                return warped
            
            front_quad, back_quad = top2_sorted[0][0], top2_sorted[1][0]
            
            # Warp to standard size
            front_crop = warp_to_cr80(cv_image, front_quad, CR80_SIZE_300)
            back_crop = warp_to_cr80(cv_image, back_quad, CR80_SIZE_300)
            
            # Convert back to PIL format
            self.cropped_front = Image.fromarray(cv2.cvtColor(front_crop, cv2.COLOR_BGR2RGB))
            self.cropped_back = Image.fromarray(cv2.cvtColor(back_crop, cv2.COLOR_BGR2RGB))
            
            print(f"Advanced PAN detection successful: found {len(unique_candidates)} candidates")
            return True
            
        else:
            print(f"Advanced PAN detection found only {len(unique_candidates)} candidates, trying template matching...")
            # Try template matching as a fallback
            return self.template_match_pan_cards(cv_image, gray)

    def template_match_pan_cards(self, cv_image, gray):
        """Try template matching for PAN card detection"""
        try:
            print("Attempting template matching for PAN cards...")
            
            # Look for regions with high text density that might be PAN cards
            # Try different ROI sizes based on typical PAN card dimensions
            H, W = gray.shape[:2]
            
            # Try to find rectangular regions with text
            candidates = []
            
            # Scan the image for potential PAN card regions
            step = 50
            for y in range(0, H - 200, step):
                for x in range(0, W - 300, step):
                    # Check a region that could be a PAN card
                    roi = gray[y:y+200, x:x+300]
                    if roi.size == 0:
                        continue
                    
                    # Calculate text density
                    _, text_mask = cv2.threshold(roi, 200, 255, cv2.THRESH_BINARY_INV)
                    text_density = np.sum(text_mask > 0) / float(roi.size)
                    
                    # PAN cards should have moderate text density
                    if 0.1 <= text_density <= 0.6:
                        candidates.append((x, y, 300, 200, text_density))
            
            if len(candidates) >= 2:
                # Sort by text density (closest to 0.3 preferred)
                candidates.sort(key=lambda x: abs(x[4] - 0.3))
                top2 = candidates[:2]
                top2_sorted = sorted(top2, key=lambda x: x[1])  # Sort by Y position
                
                # Crop the detected regions
                x1, y1, w1, h1, _ = top2_sorted[0]
                x2, y2, w2, h2, _ = top2_sorted[1]
                
                # Add some padding
                padding = 20
                x1 = max(0, x1 - padding)
                y1 = max(0, y1 - padding)
                w1 = min(cv_image.shape[1] - x1, w1 + 2 * padding)
                h1 = min(cv_image.shape[0] - y1, h1 + 2 * padding)
                
                x2 = max(0, x2 - padding)
                y2 = max(0, y2 - padding)
                w2 = min(cv_image.shape[1] - x2, w2 + 2 * padding)
                h2 = min(cv_image.shape[0] - y2, h2 + 2 * padding)
                
                # Crop and resize to standard size
                front_crop = cv_image[y1:y1+h1, x1:x1+w1]
                back_crop = cv_image[y2:y2+h2, x2:x2+w2]
                
                front_crop = cv2.resize(front_crop, (1012, 638))
                back_crop = cv2.resize(back_crop, (1012, 638))
                
                # Convert back to PIL format
                self.cropped_front = Image.fromarray(cv2.cvtColor(front_crop, cv2.COLOR_BGR2RGB))
                self.cropped_back = Image.fromarray(cv2.cvtColor(back_crop, cv2.COLOR_BGR2RGB))
                
                print(f"Template matching found {len(candidates)} PAN card candidates")
                return True
                
        except Exception as e:
            print(f"Template matching failed: {e}")
        
        print("Template matching also failed, falling back to coordinates")
        return False

    def fallback_to_coordinates(self):
        """Fallback to coordinate-based cropping when CV fails"""
        if not self.full_image:
            return

        width, height = self.full_image.size
        
        # Standard PAN card coordinates for reference PDF size
        reference_width = 2480
        reference_height = 3509
        
        front_left = 286
        front_right = 1262
        front_top = 2714
        front_bottom = 3327
        
        back_left = 1285
        back_right = 2261
        back_top = 2714
        back_bottom = 3327
        
        # Scale coordinates if document size differs
        if width != reference_width or height != reference_height:
            scale_x = width / reference_width
            scale_y = height / reference_height
            
            front_left = int(front_left * scale_x)
            front_right = int(front_right * scale_x)
            front_top = int(front_top * scale_y)
            front_bottom = int(front_bottom * scale_y)
            
            back_left = int(back_left * scale_x)
            back_right = int(back_right * scale_x)
            back_top = int(back_top * scale_y)
            back_bottom = int(back_bottom * scale_y)

        # Apply cropping
        self.cropped_front = self.full_image.crop((front_left, front_top, front_right, front_bottom))
        self.cropped_back = self.full_image.crop((back_left, back_top, back_right, back_bottom))
        
        # Resize to standard PVC size
        self.cropped_front = self.cropped_front.resize((self.pvc_width, self.pvc_height), Image.Resampling.LANCZOS)
        self.cropped_back = self.cropped_back.resize((self.pvc_width, self.pvc_height), Image.Resampling.LANCZOS)

    def get_processed_images(self):
        images = {}
        if self.cropped_front:
            images['front'] = self.cropped_front
        if self.cropped_back:
            images['back'] = self.cropped_back
        return images

class VoterProcessor:
    def __init__(self, file_stream, password=None):
        self.file_stream = file_stream
        self.password = password
        self.pdf_document = None
        self.full_image = None
        self.front_image = None
        self.back_image = None
        self.cropped_front = None
        self.cropped_back = None

    def process(self):
        try:
            self.load_pdf()
            self.split_front_back_from_single_page(self.full_image)
            self.auto_crop()
            return self.get_processed_images()
        except Exception as e:
            raise Exception(f"Voter processing failed: {str(e)}")

    def load_pdf(self):
        try:
            self.pdf_document = fitz.open(stream=self.file_stream, filetype="pdf")
            if self.pdf_document.needs_pass:
                if not self.password or not self.pdf_document.authenticate(self.password):
                    if not self.pdf_document.authenticate(""):
                        raise Exception("PDF is password protected and the provided password is not correct.")
            
            if len(self.pdf_document) > 0:
                page = self.pdf_document[0]
                pix = page.get_pixmap(matrix=fitz.Matrix(3, 3))
                img_data = pix.tobytes("ppm")
                self.full_image = Image.open(io.BytesIO(img_data))

        except Exception as e:
            raise Exception(f"Failed to load PDF: {str(e)}")

    def split_front_back_from_single_page(self, image):
        width, height = image.size
        
        # Try text density analysis first
        cv_image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
        gray = cv2.cvtColor(cv_image, cv2.COLOR_BGR2GRAY)
        
        _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)
        
        horizontal_profile = np.sum(thresh, axis=1)
        
        try:
            smoothed_profile = ndimage.gaussian_filter1d(horizontal_profile, sigma=5)
        except:
            smoothed_profile = horizontal_profile
        
        content_threshold = np.mean(smoothed_profile) + 0.5 * np.std(smoothed_profile)
        content_regions = smoothed_profile > content_threshold
        
        content_starts = []
        content_ends = []
        in_content = False
        
        for i, is_content in enumerate(content_regions):
            if is_content and not in_content:
                content_starts.append(i)
                in_content = True
            elif not is_content and in_content:
                content_ends.append(i)
                in_content = False
        
        if in_content:
            content_ends.append(len(content_regions))
        
        if len(content_starts) >= 2 and len(content_ends) >= 2:
            regions = []
            for i in range(min(len(content_starts), len(content_ends))):
                start = content_starts[i]
                end = content_ends[i]
                size = end - start
                if size > height * 0.05:
                    regions.append((start, end, size))
            
            if len(regions) >= 2:
                regions.sort(key=lambda x: x[2], reverse=True)
                main_regions = sorted(regions[:2], key=lambda x: x[0])
                
                front_start = max(0, main_regions[0][0] - 20)
                front_end = min(height, main_regions[0][1] + 20)
                
                back_start = max(0, main_regions[1][0] - 20)
                back_end = min(height, main_regions[1][1] + 20)
                
                self.front_image = image.crop((0, front_start, width, front_end))
                self.back_image = image.crop((0, back_start, width, back_end))
                return

        # Fallback to hardcoded coordinates
        reference_width = 2480
        reference_height = 3509
        reference_front_left = 132
        reference_front_right = 1161
        reference_front_top = 392
        reference_front_bottom = 1041
        reference_back_left = 1359
        reference_back_right = 2388
        reference_back_top = 392
        reference_back_bottom = 1041
        
        if width == reference_width and height == reference_height:
            front_left = reference_front_left
            front_right = reference_front_right
            front_top = reference_front_top
            front_bottom = reference_front_bottom
            
            back_left = reference_back_left
            back_right = reference_back_right
            back_top = reference_back_top
            back_bottom = reference_back_bottom
        else:
            scale_x = width / reference_width
            scale_y = height / reference_height
            
            front_left = int(reference_front_left * scale_x)
            front_right = int(reference_front_right * scale_x)
            front_top = int(reference_front_top * scale_y)
            front_bottom = int(reference_front_bottom * scale_y)
            
            back_left = int(reference_back_left * scale_x)
            back_right = int(reference_back_right * scale_x)
            back_top = int(reference_back_top * scale_y)
            back_bottom = int(reference_back_bottom * scale_y)

        self.front_image = image.crop((front_left, front_top, front_right, front_bottom))
        self.back_image = image.crop((back_left, back_top, back_right, back_bottom))

    def auto_crop(self):
        if self.front_image:
            self.cropped_front = self.front_image
        if self.back_image:
            self.cropped_back = self.back_image

    def get_processed_images(self):
        images = {}
        if self.cropped_front:
            images['front'] = self.cropped_front
        if self.cropped_back:
            images['back'] = self.cropped_back
        return images

class DLProcessor:
    def __init__(self, file_stream, password=None):
        self.file_stream = file_stream
        self.password = password
        self.pdf_document = None
        self.front_image = None
        self.back_image = None
        self.cropped_front = None
        self.cropped_back = None

    def process(self):
        try:
            self.load_pdf()
            self.extract_pages()
            self.auto_crop()
            return self.get_processed_images()
        except Exception as e:
            raise Exception(f"DL processing failed: {str(e)}")

    def load_pdf(self):
        try:
            self.pdf_document = fitz.open(stream=self.file_stream, filetype="pdf")
            if self.pdf_document.needs_pass:
                if not self.password or not self.pdf_document.authenticate(self.password):
                    if not self.pdf_document.authenticate(""):
                        raise Exception("PDF is password protected and the provided password is not correct.")
        except Exception as e:
            raise Exception(f"Failed to load PDF: {str(e)}")

    def extract_pages(self):
        if not self.pdf_document:
            return

        if len(self.pdf_document) >= 1:
            front_page = self.pdf_document[0]
            front_pix = front_page.get_pixmap(matrix=fitz.Matrix(3, 3))
            front_img_data = front_pix.tobytes("ppm")
            front_full_image = Image.open(io.BytesIO(front_img_data))
            self.front_image = self.crop_dl_page(front_full_image, "front")

        if len(self.pdf_document) >= 2:
            back_page = self.pdf_document[1]
            back_pix = back_page.get_pixmap(matrix=fitz.Matrix(3, 3))
            back_img_data = back_pix.tobytes("ppm")
            back_full_image = Image.open(io.BytesIO(back_img_data))
            self.back_image = self.crop_dl_page(back_full_image, "back")

    def crop_dl_page(self, image, page_type):
        width, height = image.size
        
        reference_page_width = 1009
        reference_page_height = 638
        
        reference_left = 0
        reference_right = 1009
        reference_top = 7
        reference_bottom = 625
        
        if width != reference_page_width or height < reference_height:
            scale_x = width / reference_page_width
            scale_y = height / reference_page_height
            
            crop_left = int(reference_left * scale_x)
            crop_right = min(int(reference_right * scale_x), width)
            crop_top = int(reference_top * scale_y)
            crop_bottom = min(int(reference_bottom * scale_y), height)
        else:
            crop_left = reference_left
            crop_right = min(reference_right, width)
            crop_top = reference_top
            crop_bottom = min(reference_bottom, height)

        return image.crop((crop_left, crop_top, crop_right, crop_bottom))

    def auto_crop(self):
        if self.front_image:
            self.cropped_front = self.front_image
        if self.back_image:
            self.cropped_back = self.back_image

    def get_processed_images(self):
        images = {}
        if self.cropped_front:
            images['front'] = self.cropped_front
        if self.cropped_back:
            images['back'] = self.cropped_back
        return images

class RCProcessor:
    def __init__(self, file_stream, password=None):
        self.file_stream = file_stream
        self.password = password
        self.pdf_document = None
        self.front_image = None
        self.back_image = None
        self.cropped_front = None
        self.cropped_back = None
        self.pvc_width = 1012
        self.pvc_height = 638

    def process(self):
        try:
            self.load_pdf()
            self.extract_pages()
            self.auto_crop()
            return self.get_processed_images()
        except Exception as e:
            raise Exception(f"RC processing failed: {str(e)}")

    def load_pdf(self):
        try:
            self.pdf_document = fitz.open(stream=self.file_stream, filetype="pdf")
            if self.pdf_document.needs_pass:
                if not self.password or not self.pdf_document.authenticate(self.password):
                    if not self.pdf_document.authenticate(""):
                        raise Exception("PDF is password protected and the provided password is not correct.")
        except Exception as e:
            raise Exception(f"Failed to load PDF: {str(e)}")

    def extract_pages(self):
        if not self.pdf_document:
            return

        if len(self.pdf_document) >= 1:
            front_page = self.pdf_document[0]
            front_pix = front_page.get_pixmap(matrix=fitz.Matrix(3, 3))
            front_img_data = front_pix.tobytes("ppm")
            front_full_image = Image.open(io.BytesIO(front_img_data))
            self.front_image = self.crop_rc_page(front_full_image, "front")

        if len(self.pdf_document) >= 2:
            back_page = self.pdf_document[1]
            back_pix = back_page.get_pixmap(matrix=fitz.Matrix(3, 3))
            back_img_data = back_pix.tobytes("ppm")
            back_full_image = Image.open(io.BytesIO(back_img_data))
            self.back_image = self.crop_rc_page(back_full_image, "back")

    def crop_rc_page(self, image, page_type):
        width, height = image.size
        
        reference_page_width = 1084
        reference_page_height = 676
        
        reference_left = 0
        reference_right = 1084
        reference_top = 0
        reference_bottom = 676
        
        if width != reference_page_width or height != reference_page_height:
            scale_x = width / reference_page_width
            scale_y = height / reference_page_height
            
            scale = min(scale_x, scale_y)
            
            crop_left = int(reference_left * scale)
            crop_right = min(int(reference_right * scale), width)
            crop_top = int(reference_top * scale)
            crop_bottom = min(int(reference_bottom * scale), height)
        else:
            crop_left = reference_left
            crop_right = min(reference_right, width)
            crop_top = reference_top
            crop_bottom = min(reference_bottom, height)

        return image.crop((crop_left, crop_top, crop_right, crop_bottom))

    def auto_crop(self):
        if self.front_image:
            self.cropped_front = self.front_image.resize((self.pvc_width, self.pvc_height), Image.Resampling.LANCZOS)
        if self.back_image:
            self.cropped_back = self.back_image.resize((self.pvc_width, self.pvc_height), Image.Resampling.LANCZOS)

    def get_processed_images(self):
        images = {}
        if self.cropped_front:
            images['front'] = self.cropped_front
        if self.cropped_back:
            images['back'] = self.cropped_back
        return images

class ABHAProcessor:
    def __init__(self, file_stream, password=None):
        self.file_stream = file_stream
        self.password = password
        self.pdf_document = None
        self.full_image = None
        self.front_image = None
        self.back_image = None
        self.cropped_front = None
        self.cropped_back = None

    def process(self):
        try:
            self.load_pdf()
            self.auto_crop()
            return self.get_processed_images()
        except Exception as e:
            raise Exception(f"ABHA processing failed: {str(e)}")

    def load_pdf(self):
        try:
            self.pdf_document = fitz.open(stream=self.file_stream, filetype="pdf")
            if self.pdf_document.needs_pass:
                if not self.password or not self.pdf_document.authenticate(self.password):
                    if not self.pdf_document.authenticate(""):
                        raise Exception("PDF is password protected and the provided password is not correct.")
            
            if len(self.pdf_document) > 0:
                page = self.pdf_document[0]
                pix = page.get_pixmap(matrix=fitz.Matrix(3, 3))
                img_data = pix.tobytes("ppm")
                self.full_image = Image.open(io.BytesIO(img_data))

        except Exception as e:
            raise Exception(f"Failed to load PDF: {str(e)}")

    def auto_crop(self):
        if not self.full_image:
            return

        width, height = self.full_image.size
        
        # ABHA card coordinates for reference PDF size
        reference_width = 1938
        reference_height = 2400
        
        front_left = 40
        front_right = 1898
        front_top = 40
        front_bottom = 1182
        
        back_left = 40
        back_right = 1898
        back_top = 1218
        back_bottom = 2360
        
        # Scale coordinates if document size differs
        if width != reference_width or height != reference_height:
            scale_x = width / reference_width
            scale_y = height / reference_height
            
            front_left = int(front_left * scale_x)
            front_right = int(front_right * scale_x)
            front_top = int(front_top * scale_y)
            front_bottom = int(front_bottom * scale_y)
            
            back_left = int(back_left * scale_x)
            back_right = int(back_right * scale_x)
            back_top = int(back_top * scale_y)
            back_bottom = int(back_bottom * scale_y)

        # Apply cropping
        self.front_image = self.full_image.crop((front_left, front_top, front_right, front_bottom))
        self.back_image = self.full_image.crop((back_left, back_top, back_right, back_bottom))
        
        self.cropped_front = self.front_image
        self.cropped_back = self.back_image

    def get_processed_images(self):
        images = {}
        if self.cropped_front:
            images['front'] = self.cropped_front
        if self.cropped_back:
            images['back'] = self.cropped_back
        return images

class AyushmanProcessor:
    def __init__(self, file_stream, password=None):
        self.file_stream = file_stream
        self.password = password
        self.pdf_document = None
        self.full_image = None
        self.front_image = None
        self.back_image = None
        self.cropped_front = None
        self.cropped_back = None
        self.pvc_width = 1012
        self.pvc_height = 638

    def process(self):
        try:
            self.load_pdf()
            self.auto_crop()
            return self.get_processed_images()
        except Exception as e:
            raise Exception(f"Ayushman processing failed: {str(e)}")

    def load_pdf(self):
        try:
            self.pdf_document = fitz.open(stream=self.file_stream, filetype="pdf")
            if self.pdf_document.needs_pass:
                if not self.password or not self.pdf_document.authenticate(self.password):
                    if not self.pdf_document.authenticate(""):
                        raise Exception("PDF is password protected and the provided password is not correct.")
            
            if len(self.pdf_document) > 0:
                page = self.pdf_document[0]
                pix = page.get_pixmap(matrix=fitz.Matrix(3, 3))
                img_data = pix.tobytes("ppm")
                self.full_image = Image.open(io.BytesIO(img_data))

        except Exception as e:
            raise Exception(f"Failed to load PDF: {str(e)}")

    def auto_crop(self):
        if not self.full_image:
            return

        width, height = self.full_image.size
        
        # Ayushman Bharat card coordinates for standard A4 PDF size (2480x3509)
        # These coordinates are based on typical Ayushman card placement in PDF documents
        reference_width = 2480
        reference_height = 3509
        
        # Front side coordinates (left side of the page)
        front_left = 286
        front_right = 1262
        front_top = 2714
        front_bottom = 3327
        
        # Back side coordinates (right side of the page)  
        back_left = 1285
        back_right = 2261
        back_top = 2714
        back_bottom = 3327
        
        # Scale coordinates if document size differs from reference
        if width != reference_width or height != reference_height:
            scale_x = width / reference_width
            scale_y = height / reference_height
            
            front_left = int(front_left * scale_x)
            front_right = int(front_right * scale_x)
            front_top = int(front_top * scale_y)
            front_bottom = int(front_bottom * scale_y)
            
            back_left = int(back_left * scale_x)
            back_right = int(back_right * scale_x)
            back_top = int(back_top * scale_y)
            back_bottom = int(back_bottom * scale_y)

        # Apply cropping with boundary checks
        front_left = max(0, front_left)
        front_right = min(width, front_right)
        front_top = max(0, front_top)
        front_bottom = min(height, front_bottom)
        
        back_left = max(0, back_left)
        back_right = min(width, back_right)
        back_top = max(0, back_top)
        back_bottom = min(height, back_bottom)

        # Crop the images
        self.front_image = self.full_image.crop((front_left, front_top, front_right, front_bottom))
        self.back_image = self.full_image.crop((back_left, back_top, back_right, back_bottom))
        
        # Resize to standard PVC card size
        self.cropped_front = self.front_image.resize((self.pvc_width, self.pvc_height), Image.Resampling.LANCZOS)
        self.cropped_back = self.back_image.resize((self.pvc_width, self.pvc_height), Image.Resampling.LANCZOS)

    def get_processed_images(self):
        images = {}
        if self.cropped_front:
            images['front'] = self.cropped_front
        if self.cropped_back:
            images['back'] = self.cropped_back
        return images

class EshramProcessor:
    def __init__(self, file_stream, password=None):
        self.file_stream = file_stream
        self.password = password
        self.pdf_document = None
        self.full_image = None
        self.front_image = None
        self.back_image = None
        self.cropped_front = None
        self.cropped_back = None

    def process(self):
        try:
            self.load_pdf()
            self.auto_crop()
            return self.get_processed_images()
        except Exception as e:
            raise Exception(f"E-Shram processing failed: {str(e)}")

    def load_pdf(self):
        try:
            self.pdf_document = fitz.open(stream=self.file_stream, filetype="pdf")
            if self.pdf_document.needs_pass:
                if not self.password or not self.pdf_document.authenticate(self.password):
                    if not self.pdf_document.authenticate(""):
                        raise Exception("PDF is password protected and the provided password is not correct.")
            
            if len(self.pdf_document) > 0:
                page = self.pdf_document[0]
                pix = page.get_pixmap(matrix=fitz.Matrix(3, 3))
                img_data = pix.tobytes("ppm")
                self.full_image = Image.open(io.BytesIO(img_data))

        except Exception as e:
            raise Exception(f"Failed to load PDF: {str(e)}")

    def auto_crop(self):
        if not self.full_image:
            return

        width, height = self.full_image.size
        
        reference_width = 2500
        reference_height = 3334
        
        front_left = 758
        front_right = 1716
        front_top = 236
        front_bottom = 851
        
        back_left = 758
        back_right = 1716
        back_top = 855
        back_bottom = 1470
        
        if width != reference_width or height != reference_height:
            scale_x = width / reference_width
            scale_y = height / reference_height
            
            front_left = int(front_left * scale_x)
            front_right = int(front_right * scale_x)
            front_top = int(front_top * scale_y)
            front_bottom = int(front_bottom * scale_y)
            
            back_left = int(back_left * scale_x)
            back_right = int(back_right * scale_x)
            back_top = int(back_top * scale_y)
            back_bottom = int(back_bottom * scale_y)

        self.front_image = self.full_image.crop((front_left, front_top, front_right, front_bottom))
        self.back_image = self.full_image.crop((back_left, back_top, back_right, back_bottom))
        
        self.cropped_front = self.front_image
        self.cropped_back = self.back_image

    def get_processed_images(self):
        images = {}
        if self.cropped_front:
            images['front'] = self.cropped_front
        if self.cropped_back:
            images['back'] = self.cropped_back
        return images
