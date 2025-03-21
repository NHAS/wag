// Function to copy text to clipboard
export const copyToClipboard =  (text: string): Promise<boolean> => {
    // Check if the Clipboard API is available
    if (!navigator.clipboard) {
        console.error('Clipboard API not available');
        return Promise.resolve(false);
    }

    // Use the Clipboard API to write text
    return navigator.clipboard.writeText(text)
        .then(() => {
            console.log('Text copied to clipboard');
            return true;
        })
        .catch(err => {
            console.error('Failed to copy text: ', err);
            return false;
        });
}