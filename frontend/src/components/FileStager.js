import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { useState } from 'react';
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
export function FileStager() {
    const [files, setFiles] = useState([]);
    const [input, setInput] = useState('');
    const [status, setStatus] = useState('');
    const handleAddFile = () => {
        if (input.trim()) {
            setFiles([...files, input.trim()]);
            setInput('');
        }
    };
    const handleStage = async () => {
        try {
            const response = await fetch('http://localhost:3001/api/add', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ files }),
            });
            const data = await response.json();
            setStatus(data.message);
            if (data.success)
                setFiles([]);
        }
        catch (error) {
            setStatus('Failed to stage files.');
        }
    };
    return (_jsxs(Card, { className: "w-full max-w-md mt-4", children: [_jsx(CardHeader, { children: _jsx(CardTitle, { children: "Stage Files" }) }), _jsxs(CardContent, { className: "space-y-4", children: [_jsxs("div", { className: "flex gap-2", children: [_jsx(Input, { placeholder: "e.g., src/main.ts or .", value: input, onChange: (e) => setInput(e.target.value), onKeyDown: (e) => e.key === 'Enter' && handleAddFile() }), _jsx(Button, { onClick: handleAddFile, children: "Add" })] }), _jsx("div", { className: "flex flex-wrap gap-2", children: files.map((file, index) => (_jsx(Badge, { variant: "secondary", children: file }, index))) }), _jsx(Button, { onClick: handleStage, disabled: files.length === 0, className: "w-full", children: "Stage Selected Files" }), status && _jsx("p", { className: "text-sm text-muted-foreground", children: status })] })] }));
}
