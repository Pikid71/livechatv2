// Voice Chat Handler - Add to index.html
class VoiceChat {
    constructor(socket, roomName, username) {
        this.socket = socket;
        this.roomName = roomName;
        this.username = username;
        this.localStream = null;
        this.peerConnections = {};
        this.isVoiceActive = false;
        
        this.configuration = {
            iceServers: [
                { urls: 'stun:stun.l.google.com:19302' },
                { urls: 'stun:stun1.l.google.com:19302' }
            ]
        };
    }
    
    async startVoice() {
        try {
            this.localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
            this.isVoiceActive = true;
            
            this.socket.emit('join_voice', { roomName: this.roomName });
            this.socket.on('user_joined_voice', (data) => this.handleUserJoined(data));
            this.socket.on('voice_offer', (data) => this.handleVoiceOffer(data));
            this.socket.on('voice_answer', (data) => this.handleVoiceAnswer(data));
            this.socket.on('ice_candidate', (data) => this.handleIceCandidate(data));
            this.socket.on('user_left_voice', (data) => this.handleUserLeft(data));
            
            return true;
        } catch (err) {
            console.error('Voice chat error:', err);
            return false;
        }
    }
    
    stopVoice() {
        if (this.localStream) {
            this.localStream.getTracks().forEach(track => track.stop());
            this.localStream = null;
        }
        
        Object.values(this.peerConnections).forEach(pc => pc.close());
        this.peerConnections = {};
        this.isVoiceActive = false;
        
        this.socket.emit('leave_voice', { roomName: this.roomName });
    }
    
    // WebRTC signaling handlers...
}