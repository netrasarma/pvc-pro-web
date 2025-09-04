#!/usr/bin/env python3
"""
Test script for PAN Processor debugging
"""

import os
import sys
from document_processor import PanProcessor

def test_pan_processor():
    """Test the PAN processor with debugging output"""
    print("=== PAN Processor Debug Test ===")
    
    # Check if test PDF exists
    test_pdf_path = "test_pan.pdf"
    if not os.path.exists(test_pdf_path):
        print(f"Test PDF not found at: {test_pdf_path}")
        print("Please place a PAN card PDF file named 'test_pan.pdf' in the current directory")
        return False
    
    try:
        # Read the test PDF
        with open(test_pdf_path, 'rb') as f:
            file_stream = f.read()
        
        # Create processor
        processor = PanProcessor(file_stream)
        
        print("Loading PDF...")
        processor.load_pdf()
        
        if processor.full_image:
            print(f"PDF loaded successfully. Image size: {processor.full_image.size}")
            
            print("\nStarting advanced PAN detection...")
            # Convert to OpenCV format for processing
            import cv2
            import numpy as np
            cv_image = cv2.cvtColor(np.array(processor.full_image), cv2.COLOR_RGB2BGR)
            
            # Test the advanced detection
            success = processor.detect_pan_cards_advanced(cv_image)
            
            if success:
                print("✓ Advanced PAN detection successful!")
                if processor.cropped_front:
                    print(f"Front crop size: {processor.cropped_front.size}")
                if processor.cropped_back:
                    print(f"Back crop size: {processor.cropped_back.size}")
            else:
                print("✗ Advanced PAN detection failed, falling back to coordinates...")
                processor.fallback_to_coordinates()
                if processor.cropped_front:
                    print(f"Front crop size (coordinates): {processor.cropped_front.size}")
                if processor.cropped_back:
                    print(f"Back crop size (coordinates): {processor.cropped_back.size}")
                
        else:
            print("Failed to load PDF image")
            return False
            
        return True
        
    except Exception as e:
        print(f"Error during testing: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_pan_processor()
    if success:
        print("\n✓ Test completed successfully!")
    else:
        print("\n✗ Test failed!")
        sys.exit(1)
