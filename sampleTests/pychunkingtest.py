import cv2
import os

def generate_video_chunks(video_path, chunk_size=1024*1024):
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        print("Error: Could not open video.")
        return

    output_dir = "video_chunks"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    chunk_count = 0
    current_chunk_size = 0
    current_chunk = None
    frame_size = None

    while True:
        ret, frame = cap.read()
        if not ret:
            break

        if current_chunk is None:
            chunk_count += 1
            chunk_path = os.path.join(output_dir, f"chunk_{chunk_count:03d}.avi")
            frame_size = (frame.shape[1], frame.shape[0])
            fourcc = cv2.VideoWriter_fourcc(*'XVID')
            print("chunk path now is, ",chunk_path)
            current_chunk = cv2.VideoWriter(chunk_path, fourcc, 30.0, frame_size)

        current_chunk.write(frame)
        current_chunk_size += frame.nbytes

        if current_chunk_size >= chunk_size:
            current_chunk.release()
            current_chunk = None
            current_chunk_size = 0

    if current_chunk is not None:
        current_chunk.release()

    cap.release()
    cv2.destroyAllWindows()

# Example usage:
video_path = "../Videos/ishq.mp4"
generate_video_chunks(video_path)
