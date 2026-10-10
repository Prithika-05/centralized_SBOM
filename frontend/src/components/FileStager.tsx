import { useState } from 'react';
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

export function FileStager() {
  const [files, setFiles] = useState<string[]>([]);
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
      if (data.success) setFiles([]);
    } catch (error) {
      setStatus('Failed to stage files.');
    }
  };

  return (
    <Card className="w-full max-w-md mt-4">
      <CardHeader>
        <CardTitle>Stage Files</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex gap-2">
          <Input 
            placeholder="e.g., src/main.ts or ." 
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleAddFile()}
          />
          <Button onClick={handleAddFile}>Add</Button>
        </div>
        
        <div className="flex flex-wrap gap-2">
          {files.map((file, index) => (
            <Badge key={index} variant="secondary">{file}</Badge>
          ))}
        </div>

        <Button onClick={handleStage} disabled={files.length === 0} className="w-full">
          Stage Selected Files
        </Button>
        
        {status && <p className="text-sm text-muted-foreground">{status}</p>}
      </CardContent>
    </Card>
  );
}