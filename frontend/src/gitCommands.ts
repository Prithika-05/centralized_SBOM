export function initializeRepo(repoName?: string): { success: boolean; message: string } {
    // 1. Declare the variable at the function's top level
    let targetFolder = ""; 

    try {
        // ... folder creation logic ...
        // 2. Assign the value here (do not use 'const' or 'let' here again)
        targetFolder = "some/path/to/repo"; 

        return { success: true, message: `Repository initialized in ${targetFolder}` };
    } catch (error) {
        return { success: false, message: `Failed to initialize: ${error}` };
    }
}

export function addFiles(filesInput: string[]): { success: boolean; message: string; staged?: string[] } {
    try {
        // Option A: If you just need to return the input array, use filesInput:
        return { 
            success: true, 
            message: 'Files staged successfully', 
            staged: filesInput 
        };
        
        /* 
        Option B: If you are creating a new array, ensure it is declared 
        outside of any nested loops or if-statements within this function:
        
        const filesToProcess = filesInput.filter(...);
        return { success: true, message: '...', staged: filesToProcess };
        */
    } catch (error) {
        return { success: false, message: `Staging failed: ${error}` };
    }
}
