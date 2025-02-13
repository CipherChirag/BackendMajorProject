import { v2 as cloudinary } from 'cloudinary';
import fs from "fs";

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const uploadOnCloudinary = async (localFilePath) => {
    if (!localFilePath) return null;

    try {
        const response = await cloudinary.uploader.upload(localFilePath, {
            resource_type: "auto",
        });
        fs.unlinkSync(localFilePath);
        return response;
    } catch (error) {
        // Retry the upload one more time.
        try {
            const responseRetry = await cloudinary.uploader.upload(localFilePath, {
                resource_type: "auto",
            });
            fs.unlinkSync(localFilePath);
            return responseRetry;
        } catch (retryError) {
            // If retry fails, then delete the local file and return null.
            fs.unlinkSync(localFilePath);
            return null;
        }
    }
}

export default uploadOnCloudinary;