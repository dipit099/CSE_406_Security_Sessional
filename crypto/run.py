from PIL import Image, ImageDraw

IMAGE_SIZE = 64

def generate_test_image(path, size=IMAGE_SIZE):
    img = Image.new("RGB", (size, size), color=(20, 20, 110))
    draw = ImageDraw.Draw(img)
    draw.ellipse([6, 6, size - 6, size - 6], fill=(255, 210, 0))
    draw.rectangle([22, 22, size - 22, size - 22], fill=(200, 20, 20))
    img.save(path, format="BMP")

generate_test_image("./final_sample_small.bmp", size=IMAGE_SIZE)